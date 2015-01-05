__author__ = 'kalrey'

import cPickle as pickle
import cStringIO
import hashlib
from contextlib import contextmanager
from swift.common.exceptions import DiskFileQuarantined, DiskFileNotExist, \
    DiskFileCollision, DiskFileDeleted, DiskFileNotOpen

from swift.common.utils import Timestamp

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.transport import THttpClient
from thrift.protocol import TBinaryProtocol
from thrift.Thrift import TException, TApplicationException

from swift.obj.backend.hbase.HbaseClient.Hbase import Client as HbaseClient
from swift.obj.backend.hbase.HbaseClient.ttypes import Mutation
from swift.obj.backend.hbase.HbaseClient.constants import *

PICKLE_PROTOCOL = 2
DEFUALT_HBASE_HOST = '127.0.0.1'
DEFAULT_HBASE_PORT = 10000

HBASE_COLUMN_VALUE = 'r:d'
HBASE_COLUMN_META = 'r:meta'
HABSE_COLUMN_ASYNCPENDING = 'r:updater'
HBASE_COLUMN_ORIGINKEY = 'm:origin_key'

class HbaseBackend(object):
    """
    A backend with hbase.
    """

    def __init__(self, conf, logger=None):
        self.logger = logger
        hbase_addrs = conf.get('hbase_addrs', None)
        if hbase_addrs:
            if ':' in hbase_addrs:
                host, port = hbase_addrs.split(':')
                port = int(port)
            else:
                host = hbase_addrs
                port = DEFAULT_HBASE_PORT
        else:
            host = DEFUALT_HBASE_HOST
            port = DEFAULT_HBASE_PORT
        self.logger.info('host %s port %s' % (host, port))
        framed = conf.get('hbase_framed', 'false')
        framed = framed.lower() == 'true'
        socket = TSocket.TSocket(host, port)
        if framed:
            self._transport = TTransport.TFramedTransport(socket)
        else:
            self._transport = TTransport.TBufferedTransport(socket)
        self._transport.open()
        self._protocol = TBinaryProtocol.TBinaryProtocol(self._transport)
        self._hbaseClient = HbaseClient(self._protocol)

        self._value_column_name = conf.get('hbase_column_value_name', HBASE_COLUMN_VALUE)
        self._meta_column_name = conf.get('hbase_column_meta_name', HBASE_COLUMN_META)
        self._asyncpending_column_name = conf.get('hbase_column_asyncpending_name', HABSE_COLUMN_ASYNCPENDING)
        self._originkey_column_name = conf.get('hbase_column_originkey_name', HBASE_COLUMN_ORIGINKEY)

    def __del__(self):
        pass

    def get_object(self, table, name):
        try:
            row_result = self._hbaseClient.getRow(tableName=table,
                                                  row=name,
                                                  attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})
        except TException,e:
            self.logger.error()
        if row_result is None or len(row_result) == 0:
            data, metadata = None, None
        else:
            data = row_result[0].columns.get(self._value_column_name)
            data = cStringIO.StringIO(data.value) if data else None
            metadata = row_result[0].columns.get(self._meta_column_name)
            metadata = pickle.loads(metadata.value) if metadata else ''
            origin_key = row_result[0].columns.get(self._originkey_column_name)
            metadata['name'] = origin_key
        return data, metadata

    def read_metadata(self, table, name):
        metadata = ''
        #metadata is a list of TCell
        try:
            cells = self._hbaseClient.get(tableName=table,
                                          row=name,
                                          column=self._meta_column_name,
                                          attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})
            if cells:
                metadata = cells[0].value
        except TException:
            pass
        return pickle.loads(metadata)

    def put_object(self, table, name, data, metadata):
        mutations = list()
        if data:
            mutation = Mutation(column=self._value_column_name, value=data)
            mutations.append(mutation)
        if metadata:
            metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
            mutations.append(Mutation(column=self._meta_column_name, value=metastr))
        self._hbaseClient.mutateRow(tableName=table,
                                    row=name,
                                    mutations=mutations,
                                    attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})

    def async_updater(self, table, name, update_data, timestamp):
        mutations = list()
        if update_data:
            async_pending = pickle.dumps(update_data, PICKLE_PROTOCOL)
            mutations.append(Mutation(column=self._asyncpending_column_name, value=async_pending))
        self._hbaseClient.mutateRowTs(tableName=table,
                                      row=name,
                                      mutations=mutations,
                                      timestamp=timestamp,
                                      attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})

    def write_metadata(self, table, name, metadata):
        mutations = list()
        if metadata:
            metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
            mutations.append(Mutation(column=self._meta_column_name, value=metastr))
        self._hbaseClient.mutateRow(tableName=table,
                                    row=name,
                                    mutations=mutations,
                                    attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})

    def del_object(self, table, name):
        mutations = list()
        mutation = Mutation(isDelete=True, column=self._value_column_name, value='')
        mutations.append(mutation)
        mutation = Mutation(isDelete=True, column=self._meta_column_name, value='')
        mutations.append(mutation)
        mutation = Mutation(isDelete=True, column=self._asyncpending_column_name, value='')
        mutations.append(mutation)
        self._hbaseClient.mutateRow(tableName=table,
                                    row=name,
                                    mutations=mutations,
                                    attributes={METEOR_HABASE_THRIFT_ATTRIBUTES_KEY_IS_HASH: 'true'})

    def get_diskfile(self, table, account, container, obj, **kwargs):
        return DiskFile(self, table, account, container, obj)




class DiskFileWriter(object):
    """
    .. note::
        Sample alternative pluggable on-hbase backend implementation.

    Encapsulation of the write context for servicing PUT REST API
    requests. Serves as the context manager object for DiskFile's create()
    method.

    :param fs: internal file system object to use
    :param name: standard object name
    :param fp: `StringIO` in-memory representation object
    """
    def __init__(self, fs, table, name, fp):
        self._hbase_backend = fs
        self._name = name
        self._table = table
        self._fp = fp
        self._upload_size = 0

    def write(self, chunk):
        """
        Write a chunk of data into the `StringIO` object.

        :param chunk: the chunk of data to write as a string object
        """
        self._fp.write(chunk)
        self._upload_size += len(chunk)
        return self._upload_size

    def put(self, metadata):
        """
        Make the final association in the in-memory file system for this name
        with the `StringIO` object.

        :param metadata: dictionary of metadata to be written
        :param extension: extension to be used when making the file
        """
        self._fp.seek(0)
        self._hbase_backend.put_object(self._table, self._name, self._fp.read(), metadata)


class DiskFileReader(object):
    """
    .. note::
        Sample alternative pluggable on-disk backend implementation.

    Encapsulation of the read context for servicing GET REST API
    requests. Serves as the context manager object for DiskFile's reader()
    method.

    :param name: object name
    :param fp: open file object pointer reference
    :param obj_size: on-disk size of object in bytes
    :param etag: MD5 hash of object from metadata
    """
    def __init__(self, name, fp, obj_size, etag):
        self._name = name
        self._fp = fp
        self._obj_size = obj_size
        self._etag = etag
        #
        self._iter_etag = None
        self._bytes_read = 0
        self._started_at_0 = False
        self._read_to_eof = False
        self._suppress_file_closing = False
        #
        self.was_quarantined = ''

    def __iter__(self):
        try:
            self._bytes_read = 0
            self._started_at_0 = False
            self._read_to_eof = False
            if self._fp.tell() == 0:
                self._started_at_0 = True
                self._iter_etag = hashlib.md5()
            while True:
                chunk = self._fp.read()
                if chunk:
                    if self._iter_etag:
                        self._iter_etag.update(chunk)
                    self._bytes_read += len(chunk)
                    yield chunk
                else:
                    self._read_to_eof = True
                    break
        finally:
            if not self._suppress_file_closing:
                self.close()

    def app_iter_range(self, start, stop):
        if start or start == 0:
            self._fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        try:
            for chunk in self:
                if length is not None:
                    length -= len(chunk)
                    if length < 0:
                        # Chop off the extra:
                        yield chunk[:length]
                        break
                yield chunk
        finally:
            if not self._suppress_file_closing:
                self.close()

    def app_iter_ranges(self, ranges, content_type, boundary, size):
        if not ranges:
            yield ''
        else:
            try:
                self._suppress_file_closing = True
                for chunk in multi_range_iterator(
                        ranges, content_type, boundary, size,
                        self.app_iter_range):
                    yield chunk
            finally:
                self._suppress_file_closing = False
                try:
                    self.close()
                except DiskFileQuarantined:
                    pass

    def _quarantine(self, msg):
        self.was_quarantined = msg

    def _handle_close_quarantine(self):
        if self._bytes_read != self._obj_size:
            self._quarantine(
                "Bytes read: %s, does not match metadata: %s" % (
                    self.bytes_read, self._obj_size))
        elif self._iter_etag and \
                self._etag != self._iter_etag.hexdigest():
            self._quarantine(
                "ETag %s and file's md5 %s do not match" % (
                    self._etag, self._iter_etag.hexdigest()))

    def close(self):
        """
        Close the file. Will handle quarantining file if necessary.
        """
        if self._fp:
            try:
                if self._started_at_0 and self._read_to_eof:
                    self._handle_close_quarantine()
            except (Exception, Timeout):
                pass
            finally:
                self._fp = None


class DiskFile(object):
    """
    .. note::

        Sample alternative pluggable on-disk backend implementation. This
        example duck-types the reference implementation DiskFile class.

    Manage object files in-hbase.

    :param mgr: DiskFileManager
    :param device_path: path to the target device or drive
    :param threadpool: thread pool to use for blocking operations
    :param partition: partition on the device in which the object lives
    :param account: account name for the object
    :param container: container name for the object
    :param obj: object name for the object
    :param keep_cache: caller's preference for keeping data read in the cache
    """

    def __init__(self, backend, table, account, container, obj):
        self._name = '/' + '/'.join((account, container, obj))
        self._metadata = None
        self._fp = None
        self._filesystem = backend
        self._table = table

    def open(self):
        """
        Open the file and read the metadata.

        This method must populate the _metadata attribute.
        :raises DiskFileCollision: on name mis-match with metadata
        :raises DiskFileDeleted: if it does not exist, or a tombstone is
                                 present
        :raises DiskFileQuarantined: if while reading metadata of the file
                                     some data did pass cross checks
        """
        fp, self._metadata = self._filesystem.get_object(self._table, self._name)
        if fp is None:
            raise DiskFileDeleted()
        self._fp = fp
#        self._fp = self._verify_data_file(fp)
        self._metadata = self._metadata or {}
        return self

    def __enter__(self):
        if self._metadata is None:
            raise DiskFileNotOpen()
        return self

    def __exit__(self, t, v, tb):
        if self._fp is not None:
            self._fp = None

    def _quarantine(self, name, msg):
        """
        Quarantine a file; responsible for incrementing the associated logger's
        count of quarantines.

        :param data_file: full path of data file to quarantine
        :param msg: reason for quarantining to be included in the exception
        :returns: DiskFileQuarantined exception object
        """
        self._logger.warn("Quarantined object %s: %s" % (
            data_file, msg))
        self._logger.increment('quarantines')
        return DiskFileQuarantined(msg)

    def _verify_data_file(self, fp):
        """
        Verify the metadata's name value matches what we think the object is
        named.

        :raises DiskFileCollision: if the metadata stored name does not match
                                   the referenced name of the file
        :raises DiskFileNotExist: if the object has expired
        :raises DiskFileQuarantined: if data inconsistencies were detected
                                     between the metadata and the file-system
                                     metadata
        """
        try:
            mname = self._metadata['name']
        except KeyError:
            raise self._quarantine(self._name, "missing name metadata")
        else:
            if mname != self._name:
                raise DiskFileCollision('Client path does not match path '
                                        'stored in object metadata')
        try:
            x_delete_at = int(self._metadata['X-Delete-At'])
        except KeyError:
            pass
        except ValueError:
            # Quarantine, the x-delete-at key is present but not an
            # integer.
            raise self._quarantine(
                self._name, "bad metadata x-delete-at value %s" % (
                    self._metadata['X-Delete-At']))
        else:
            if x_delete_at <= time.time():
                raise DiskFileNotExist('Expired')
        try:
            metadata_size = int(self._metadata['Content-Length'])
        except KeyError:
            raise self._quarantine(
                self._name, "missing content-length in metadata")
        except ValueError:
            # Quarantine, the content-length key is present but not an
            # integer.
            raise self._quarantine(
                self._name, "bad metadata content-length value %s" % (
                    self._metadata['Content-Length']))
        try:
            fp.seek(0, 2)
            obj_size = fp.tell()
            fp.seek(0, 0)
        except OSError as err:
            # Quarantine, we can't successfully stat the file.
            raise self._quarantine(self._name, "not stat-able: %s" % err)
        if obj_size != metadata_size:
            raise self._quarantine(
                self._name, "metadata content-length %s does"
                " not match actual object size %s" % (
                    metadata_size, obj_size))
        return fp

    def get_metadata(self):
        """
        Provide the metadata for an object as a dictionary.

        :returns: object's metadata dictionary
        """
        if self._metadata is None:
            raise DiskFileNotOpen()
        return self._metadata

    def read_metadata(self):
        """
        Return the metadata for an object.

        :returns: metadata dictionary for an object
        """
        with self.open():
            return self.get_metadata()

    def reader(self, keep_cache=False):
        """
        Return a swift.common.swob.Response class compatible "app_iter"
        object. The responsibility of closing the open file is passed to the
        DiskFileReader object.

        :param keep_cache:
        """
        dr = DiskFileReader(self._name, self._fp,
                            int(self._metadata['Content-Length']),
                            self._metadata['ETag'])
        # At this point the reader object is now responsible for
        # the file pointer.
        self._fp = None
        return dr

    @contextmanager
    def create(self, size=None):
        """
        Context manager to create a file. We create a temporary file first, and
        then return a DiskFileWriter object to encapsulate the state.

        :param size: optional initial size of file to explicitly allocate on
                     disk
        :raises DiskFileNoSpace: if a size is specified and allocation fails
        """
        fp = cStringIO.StringIO()
        try:
            yield DiskFileWriter(self._filesystem, self._table, self._name, fp)
        finally:
            del fp

    def write_metadata(self, metadata):
        """
        Write a block of metadata to an object.
        """
        self._filesystem.write_metadata(self._table, self._name)


    def delete(self, timestamp):
        """
        Perform a delete for the given object in the given container under the
        given account.

        This creates a tombstone file with the given timestamp, and removes
        any older versions of the object file.  Any file that has an older
        timestamp than timestamp will be deleted.

        :param timestamp: timestamp to compare with each file
        """
        fp, md = self._filesystem.get_object(self._table, self._name)
        if fp and md and md['X-Timestamp'] < Timestamp(timestamp):
            self._filesystem.del_object(self._table, self._name)