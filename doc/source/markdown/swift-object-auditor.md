本文介绍object-auditor工作方式及简单的代码分析，代码基于swift2.0版本。

## 组件简介 ##
object-auditor组件用于对磁盘上存储的object进行扫描校验，其步骤是：

- 全盘扫描
- ZBF模式下仅仅校验文件是否为0字节
- ALL模式下校验文件大小和md5是否和metadata中记录吻合
- 对于不吻合的文件，移动至quarantine，同时标记partition下的hashes.pkl

## 代码分析 ##
object-auditor组件仍然是通过manager进行启动，其中object-auditor组件的实现包含2个类：ObjectAuditor和AuditorWorker。  
ObjectAuditor派生自Daemon类，通过manager框架启动调用该类的run函数启动，该类并不执行具体的校验工作。  
AuditorWorker则执行具体的校验逻辑，核心入口为auditor_all_objects。

### ObjectAuditor ###
该类的核心入口为run函数（派生自Deamon类并且没有override）

    def run(self, once=False, **kwargs):
        """Run the daemon"""
        utils.validate_configuration()
        utils.drop_privileges(self.conf.get('user', 'swift'))
        utils.capture_stdio(self.logger, **kwargs)

        def kill_children(*args):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.killpg(0, signal.SIGTERM)
            sys.exit()

        signal.signal(signal.SIGTERM, kill_children)
        if once:
            self.run_once(**kwargs)
        else:
            self.run_forever(**kwargs)

该函数主要用于auditor组件启动，默认情况下是以Daemon启动

继续关注run_forever：

    def run_forever(self, *args, **kwargs):
        """Run the object audit until stopped."""
        # zero byte only command line option
        #默认情况下zbo_fps为0
        zbo_fps = kwargs.get('zero_byte_fps', 0)
        parent = False
        if zbo_fps:
            # only start parent
            parent = True
        kwargs = {'mode': 'forever'}

        while True:
            try:
                self.audit_loop(parent, zbo_fps, **kwargs)
            except (Exception, Timeout) as err:
                self.logger.exception(_('ERROR auditing: %s' % err))
            self._sleep()

这里我们需要留意2个参数zbo_fps和parent的默认值。

关注audit_loop:

    def audit_loop(self, parent, zbo_fps, override_devices=None, **kwargs):
        """Audit loop"""
        self.clear_recon_cache('ALL')
        self.clear_recon_cache('ZBF')
        kwargs['device_dirs'] = override_devices
        #默认parent为False
        if parent:
            kwargs['zero_byte_fps'] = zbo_fps
            self.run_audit(**kwargs)
        else:
            pids = []
            #默认self.conf_zero_byte_fps = 50
            #参见self.conf_zero_byte_fps = int(conf.get('zero_byte_files_per_second', 50))
            if self.conf_zero_byte_fps:
                #以'ZBF'方式启动子进程
                zbf_pid = self.fork_child(zero_byte_fps=True, **kwargs)
                pids.append(zbf_pid)
            #同时以'ALL'方式再启动一个子进程（kwargs中默认不包含zero_byte_fps参数）
            pids.append(self.fork_child(**kwargs))
            while pids:
                pid = os.wait()[0]
                # ZBF scanner must be restarted as soon as it finishes
                if self.conf_zero_byte_fps and pid == zbf_pid and \
                   len(pids) > 1:
                    kwargs['device_dirs'] = override_devices
                    # sleep between ZBF scanner forks
                    self._sleep()
                    zbf_pid = self.fork_child(zero_byte_fps=True, **kwargs)
                    pids.append(zbf_pid)
                pids.remove(pid)


    def fork_child(self, zero_byte_fps=False, **kwargs):
        """Child execution"""
        pid = os.fork()
        if pid:
            return pid
        else:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            if zero_byte_fps:
                kwargs['zero_byte_fps'] = self.conf_zero_byte_fps
            self.run_audit(**kwargs)
            sys.exit()


    def run_audit(self, **kwargs):
        """Run the object audit"""
        #此处mode为'forever'或者'once',默认forever
        mode = kwargs.get('mode')
        zero_byte_only_at_fps = kwargs.get('zero_byte_fps', 0)
        #device_dirs默认为None
        device_dirs = kwargs.get('device_dirs')
        #self.devices为数据盘挂载点，默认为'/srv/node'
        worker = AuditorWorker(self.conf, self.logger, self.rcache,
                               self.devices,
                               zero_byte_only_at_fps=zero_byte_only_at_fps)
        worker.audit_all_objects(mode=mode, device_dirs=device_dirs)

根据上面代码可以看到默认情况先object-auditor组件会以'ZBF'和'ALL'同时启动2个子进程。
### AuditorWorker ###
真正的处理流程在AuditorWorker::audit\_all_objects中进行，以下代码为本人整理后移除日志输出后保留核心部分的代码，便于分析展示：


    def audit_all_objects(self, mode='once', device_dirs=None):
        #all_locs为yield AuditLocation(hsh_path, device, partition)
        #其中hsh_path = os.path.join(suff_path, hsh)
        all_locs = self.diskfile_mgr.object_audit_location_generator(
            device_dirs=device_dirs)
        for location in all_locs:
            self.failsafe_object_audit(location)
            
        # Avoid divide by zero during very short runs
        elapsed = (time.time() - begin) or 0.000001
        
        # Clear recon cache entry if device_dirs is set
        if device_dirs:
            cache_entry = self.create_recon_nested_dict(
                'object_auditor_stats_%s' % (self.auditor_type),
                device_dirs, {})
            dump_recon_cache(cache_entry, self.rcache, self.logger)
        if self.stats_sizes:
            self.logger.info(
                _('Object audit stats: %s') % json.dumps(self.stats_buckets))


    def failsafe_object_audit(self, location):
        """
        Entrypoint to object_audit, with a failsafe generic exception handler.
        """
        try:
            #location即为'/<devices>/<device>/<object>/<partition>/<hash_suffix>/<hash>'
            self.object_audit(location)
        except (Exception, Timeout):
            self.logger.increment('errors')
            self.errors += 1
            self.logger.exception(_('ERROR Trying to audit %s'), location)


此处开始对单个object进行校验工作

    def object_audit(self, location):
        """
        Audits the given object location.

        :param location: an audit location
                         (from diskfile.object_audit_location_generator)
        """
        def raise_dfq(msg):
            raise DiskFileQuarantined(msg)

        try:
            #首先对location所在设备进行Mount_Check
            #然后利用location初始化一个DiskFile对象
            df = self.diskfile_mgr.get_diskfile_from_audit_location(location)
            #df.open操作会对目录下的data、meta、ts文件进行时间戳排序，选出有效的
            with df.open():
                metadata = df.get_metadata()
                obj_size = int(metadata['Content-Length'])
                #附带做一些统计操作，object大小发布情况
                if self.stats_sizes:
                    self.record_stats(obj_size)
                #'ZBF'模式下文件存在大小则直接pass
                if self.zero_byte_only_at_fps and obj_size:
                    self.passes += 1
                    return
                #'ALL'模式下进行更详细的校验工作
                reader = df.reader(_quarantine_hook=raise_dfq)
            with closing(reader):
                for chunk in reader:
                    chunk_len = len(chunk)
                    self.bytes_running_time = ratelimit_sleep(
                        self.bytes_running_time,
                        self.max_bytes_per_second,
                        incr_by=chunk_len)
                    self.bytes_processed += chunk_len
                    self.total_bytes_processed += chunk_len
        except DiskFileNotExist:
            return
        except DiskFileQuarantined as err:
            self.quarantines += 1
            self.logger.error(_('ERROR Object %(obj)s failed audit and was'
                                ' quarantined: %(err)s'),
                              {'obj': location, 'err': err})
        self.passes += 1


详细的校验代码

    def reader(self, keep_cache=False,
               _quarantine_hook=lambda m: None):
        """
        Return a :class:`swift.common.swob.Response` class compatible
        "`app_iter`" object as defined by
        :class:`swift.obj.diskfile.DiskFileReader`.

        For this implementation, the responsibility of closing the open file
        is passed to the :class:`swift.obj.diskfile.DiskFileReader` object.

        :param keep_cache: caller's preference for keeping data read in the
                           OS buffer cache
        :param _quarantine_hook: 1-arg callable called when obj quarantined;
                                 the arg is the reason for quarantine.
                                 Default is to ignore it.
                                 Not needed by the REST layer.
        :returns: a :class:`swift.obj.diskfile.DiskFileReader` object
        """
        dr = DiskFileReader(
            self._fp, self._data_file, int(self._metadata['Content-Length']),
            self._metadata['ETag'], self._threadpool, self._disk_chunk_size,
            self._mgr.keep_cache_size, self._device_path, self._logger,
            quarantine_hook=_quarantine_hook, keep_cache=keep_cache)
        # At this point the reader object is now responsible for closing
        # the file pointer.
        self._fp = None
        return dr

这里可以看到最终利用DiskFileReader进行扫描，此处重点看DsikFileReader::\_\_iter__和DsikFileReader::close

    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            dropped_cache = 0
            self._bytes_read = 0
            self._started_at_0 = False
            self._read_to_eof = False
            if self._fp.tell() == 0:
                self._started_at_0 = True
                #初始化HASH对象
                self._iter_etag = hashlib.md5()
            while True:
                chunk = self._threadpool.run_in_thread(
                    self._fp.read, self._disk_chunk_size)
                if chunk:
                    #通过叠加分片计算整体md5
                    if self._iter_etag:
                        self._iter_etag.update(chunk)
                    self._bytes_read += len(chunk)
                    if self._bytes_read - dropped_cache > (1024 * 1024):
                        self._drop_cache(self._fp.fileno(), dropped_cache,
                                         self._bytes_read - dropped_cache)
                        dropped_cache = self._bytes_read
                    yield chunk
                else:
                    self._read_to_eof = True
                    self._drop_cache(self._fp.fileno(), dropped_cache,
                                     self._bytes_read - dropped_cache)
                    break
        finally:
            if not self._suppress_file_closing:
                self.close()

    def close(self):
        """
        Close the open file handle if present.

        For this specific implementation, this method will handle quarantining
        the file if necessary.
        """
        if self._fp:
            try:
                if self._started_at_0 and self._read_to_eof:
                #完整读完则进行校验
                    self._handle_close_quarantine()
            except DiskFileQuarantined:
                raise
            except (Exception, Timeout) as e:
                self._logger.error(_(
                    'ERROR DiskFile %(data_file)s'
                    ' close failure: %(exc)s : %(stack)s'),
                    {'exc': e, 'stack': ''.join(traceback.format_stack()),
                     'data_file': self._data_file})
            finally:
                fp, self._fp = self._fp, None
                fp.close()


    def _handle_close_quarantine(self):
        """Check if file needs to be quarantined"""
        #比对读取的文件流长度和metadata中记录的Content-Length
        if self._bytes_read != self._obj_size:
            self._quarantine(
                "Bytes read: %s, does not match metadata: %s" % (
                    self._bytes_read, self._obj_size))
        #比对读取的文件流md5和metadata中记录的Etag
        elif self._iter_etag and \
                self._etag != self._iter_etag.hexdigest():
            self._quarantine(
                "ETag %s and file's md5 %s do not match" % (
                    self._etag, self._iter_etag.hexdigest()))

    def _quarantine(self, msg):
        self._quarantined_dir = self._threadpool.run_in_thread(
            quarantine_renamer, self._device_path, self._data_file)
        self._logger.warn("Quarantined object %s: %s" % (
            self._data_file, msg))
        self._logger.increment('quarantines')
        self._quarantine_hook(msg)


如果文件校验出现问题，则执行quarantine_renamer

    def quarantine_renamer(device_path, corrupted_file_path):
        """
        In the case that a file is corrupted, move it to a quarantined
        area to allow replication to fix it.

        :params device_path: The path to the device the corrupted file is on.
        :params corrupted_file_path: The path to the file you want quarantined.

        :returns: path (str) of directory the file was moved to
        :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                         exceptions from rename
        """
        #from_dir就是到hash那一层,'/<devices>/<device>/<object>/<partition>/<hash_suffix>/<hash>'
        from_dir = dirname(corrupted_file_path)
        to_dir = join(device_path, 'quarantined',
                      get_data_dir(extract_policy_index(corrupted_file_path)),
                      basename(from_dir))
        #更新partition下hashes.pkl文件中hash_suffix对应的数据
        invalidate_hash(dirname(from_dir))
        try:
            #将object对应的hash目录移至quarantine目录下
            renamer(from_dir, to_dir)
        except OSError as e:
            if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
            renamer(from_dir, to_dir)
        return to_dir

此处可以看invalidate_hash只是把对应的后缀对应项设置为None

    def invalidate_hash(suffix_dir):
    """
    Invalidates the hash for a suffix_dir in the partition's hashes file.

    :param suffix_dir: absolute path to suffix dir whose hash needs
                       invalidating
    """

    suffix = basename(suffix_dir)
    partition_dir = dirname(suffix_dir)
    hashes_file = join(partition_dir, HASH_FILE)
    with lock_path(partition_dir):
        try:
            with open(hashes_file, 'rb') as fp:
                hashes = pickle.load(fp)
            if suffix in hashes and not hashes[suffix]:
                #在pkl文件中找到后缀，同时后缀对应数值为None，那么就不需要做任何操作
                return
        except Exception:
            return
        #将对应后缀的数值改成None，写入pkl中更新
        hashes[suffix] = None
        write_pickle(hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)