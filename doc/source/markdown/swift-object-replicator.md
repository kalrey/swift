本文介绍object-replicator工作方式及简单的代码分析，代码基于swift2.X版本。

## 代码分析 ##
object-replicator组件仍然是通过manager进行启动，其中object-replicator组件的功能实现包含在ObjectReplicator中。  
ObjectReplicator派生自Daemon类，通过manager框架启动调用该类的run函数启动。 

replicator已replicat函数为业务入口

    def replicate(self, override_devices=None, override_partitions=None):
        """Run a replication pass"""
        self.start = time.time()
        self.suffix_count = 0
        self.suffix_sync = 0
        self.suffix_hash = 0
        self.replication_count = 0
        self.last_replication_count = -1
        self.partition_times = []

        if override_devices is None:
            override_devices = []
        if override_partitions is None:
            override_partitions = []
		#启动心跳协程
        stats = eventlet.spawn(self.heartbeat)
        lockup_detector = eventlet.spawn(self.detect_lockups)
        eventlet.sleep()  # Give spawns a cycle

        try:
			#根据并发数启动对应的协程数
            self.run_pool = GreenPool(size=self.concurrency)
            
			#收集待同步的作业，每个作业以partition为单位
            #job格式为
            #dict(path,          #partition本机路径
            #     device=,       #partition所在设备
            #     nodes,         #partition对应远程nodes
            #     delete,        #是否为待删除partition
            #     policy_idx,    #对应的ring-policy序号
            #     partition,     #partition序号
            #     object_ring)   #object ring
            jobs = self.collect_jobs()
            for job in jobs:
                if override_devices and job['device'] not in override_devices:
                    continue
                if override_partitions and \
                        job['partition'] not in override_partitions:
                    continue
                dev_path = join(self.devices_dir, job['device'])
                
                #mount check检查
                if self.mount_check and not ismount(dev_path):
                    self.logger.warn(_('%s is not mounted'), job['device'])
                    continue
                if not self.check_ring(job['object_ring']):
                    self.logger.info(_("Ring change detected. Aborting "
                                       "current replication pass."))
                    return

				#根据delete标记选择不同的同步策略
                if job['delete']:
                    self.run_pool.spawn(self.update_deleted, job)
                else:
                    self.run_pool.spawn(self.update, job)
            with Timeout(self.lockup_timeout):
                self.run_pool.waitall()
        except (Exception, Timeout):
            self.logger.exception(_("Exception in top-level replication loop"))
            self.kill_coros()
        finally:
            stats.kill()
            lockup_detector.kill()
            self.stats_line()


    def collect_jobs(self):
        """
        Returns a sorted list of jobs (dictionaries) that specify the
        partitions, nodes, etc to be rsynced.
        """
        jobs = []
        ips = whataremyips()
        for policy in POLICIES:
            # may need to branch here for future policy types
			#对每个ring-policy执行job收集
            self.process_repl(policy, jobs, ips)
        #将jobs的顺序随机化（暂时不是很明白用意，可能是避免单块磁盘持续高负荷IO）
        random.shuffle(jobs)
        if self.handoffs_first:
            #注意，此处官方代码注释有歧义，并非一定是handoff parts，应该是说待删除parts
            # Move the handoff parts to the front of the list
            jobs.sort(key=lambda job: not job['delete'])
        self.job_count = len(jobs)
        return jobs


	def process_repl(self, policy, jobs, ips):
        """
        Helper function for collect_jobs to build jobs for replication
        using replication style storage policy
        """
        obj_ring = self.get_object_ring(policy.idx)
        data_dir = get_data_dir(policy.idx)
        for local_dev in [dev for dev in obj_ring.devs
                          if dev and dev['replication_ip'] in ips and
                          dev['replication_port'] == self.port]:

            #依次遍历ring文件中本机设备
            dev_path = join(self.devices_dir, local_dev['device'])
            obj_path = join(dev_path, data_dir)
            tmp_path = join(dev_path, get_tmp_dir(int(policy)))

			#如果mount_check开关打开，则执行mount check动作
            if self.mount_check and not ismount(dev_path):
                self.logger.warn(_('%s is not mounted'), local_dev['device'])
                continue

            #负责释放临时文件夹中的过期文件（例如/swift/node/sdc1/objects/tmp/）
            unlink_older_than(tmp_path, time.time() - self.reclaim_age)

            if not os.path.exists(obj_path):
                try:
                    mkdirs(obj_path)
                except Exception:
                    self.logger.exception('ERROR creating %s' % obj_path)
                continue

			#遍历/swift/node/sdc1/objects下所有partition
            for partition in os.listdir(obj_path):
                try:
                    job_path = join(obj_path, partition)
                    if isfile(job_path):
						#清除掉该层目录下的文件（该层只应该出现partition目录）
                        # Clean up any (probably zero-byte) files where a
                        # partition should be.
                        self.logger.warning(
                            'Removing partition directory '
                            'which was a file: %s', job_path)
                        os.remove(job_path)
                        continue
                    #从ring文件中获取该partition对应的所有节点
                    part_nodes = obj_ring.get_part_nodes(int(partition))
                    #获取该partition除本机以外的所有节点
                    nodes = [node for node in part_nodes
                             if node['id'] != local_dev['id']]

                    #加入到jobs中，此处需要注意delete标记，当满足len(nodes) > len(part_nodes) - 1条件时，
                    #即说明本机不再是partition对应的节点，原因有多个：
                    #1.如果该partition作为handoff被暂存在该机器；
                    #2.ring文件重新更新导致该partition不再属于该设备
                    jobs.append(
                        dict(path=job_path,
                             device=local_dev['device'],
                             nodes=nodes,
                             delete=len(nodes) > len(part_nodes) - 1,
                             policy_idx=policy.idx,
                             partition=partition,
                             object_ring=obj_ring))

                except (ValueError, OSError):
                    continue


    def update_deleted(self, job):
        """
        High-level method that replicates a single partition that doesn't
        belong on this node.

        :param job: a dict containing info about the partition to be replicated
        """
		
		#该函数用于获取partition下所有的HASH后缀目录
        def tpool_get_suffixes(path):
            return [suff for suff in os.listdir(path)
                    if len(suff) == 3 and isdir(join(path, suff))]
        self.replication_count += 1
        self.logger.increment('partition.delete.count.%s' % (job['device'],))
        self.headers[POLICY_INDEX] = job['policy_idx']
        begin = time.time()
        try:
            responses = []
            #获取partition的所有HASH后缀目录
            suffixes = tpool.execute(tpool_get_suffixes, job['path'])
            if suffixes:
                for node in job['nodes']:
					#将suffixes列表中的内容推送至远端
                    success = self.sync(node, job, suffixes)
                    if success:
                        with Timeout(self.http_timeout):
                            conn = http_connect(
                                node['replication_ip'],
                                node['replication_port'],
                                node['device'], job['partition'], 'REPLICATE',
                                '/' + '-'.join(suffixes), headers=self.headers)
                            conn.getresponse().read()
                    responses.append(success)
            if self.handoff_delete:
                # delete handoff if we have had handoff_delete successes
                delete_handoff = len([resp for resp in responses if resp]) >= \
                    self.handoff_delete
            else:
                # delete handoff if all syncs were successful
                delete_handoff = len(responses) == len(job['nodes']) and \
                    all(responses)
            if not suffixes or delete_handoff:
                self.logger.info(_("Removing partition: %s"), job['path'])
                tpool.execute(shutil.rmtree, job['path'], ignore_errors=True)
        except (Exception, Timeout):
            self.logger.exception(_("Error syncing handoff partition"))
        finally:
            self.partition_times.append(time.time() - begin)
            self.logger.timing_since('partition.delete.timing', begin)


    def update(self, job):
        """
        High-level method that replicates a single partition.

        :param job: a dict containing info about the partition to be replicated
        """
        self.replication_count += 1
        self.logger.increment('partition.update.count.%s' % (job['device'],))
        self.headers[POLICY_INDEX] = job['policy_idx']
        begin = time.time()
        try:
            hashed, local_hash = tpool_reraise(
                get_hashes, job['path'],
                do_listdir=(self.replication_count % 10) == 0,
                reclaim_age=self.reclaim_age)
            self.suffix_hash += hashed
            self.logger.update_stats('suffix.hashes', hashed)
            attempts_left = len(job['nodes'])
            nodes = itertools.chain(
                job['nodes'],
                job['object_ring'].get_more_nodes(int(job['partition'])))
            while attempts_left > 0:
                # If this throws StopIterator it will be caught way below
                node = next(nodes)
                attempts_left -= 1
                try:
					#获取partition对应的远端node的pkl文件
                    with Timeout(self.http_timeout):
                        resp = http_connect(
                            node['replication_ip'], node['replication_port'],
                            node['device'], job['partition'], 'REPLICATE',
                            '', headers=self.headers).getresponse()
                        if resp.status == HTTP_INSUFFICIENT_STORAGE:
                            self.logger.error(_('%(ip)s/%(device)s responded'
                                                ' as unmounted'), node)
                            attempts_left += 1
                            continue
                        if resp.status != HTTP_OK:
                            self.logger.error(_("Invalid response %(resp)s "
                                                "from %(ip)s"),
                                              {'resp': resp.status,
                                               'ip': node['replication_ip']})
                            continue
                        remote_hash = pickle.loads(resp.read())
                        del resp
					#筛选出本机pkl中和远端pkl不一致的hash后缀（其中包含本机suffix值为None的那部分）
                    suffixes = [suffix for suffix in local_hash if
                                local_hash[suffix] !=
                                remote_hash.get(suffix, -1)]
                    if not suffixes:
                        continue

                    #重新计算这批不一致的hash后缀目录
                    hashed, recalc_hash = tpool_reraise(
                        get_hashes,
                        job['path'], recalculate=suffixes,
                        reclaim_age=self.reclaim_age)
                    self.logger.update_stats('suffix.hashes', hashed)
                    local_hash = recalc_hash

					#重新和远端传递过来的比对一次（进一步校验，PS：校验的开销比数据同步要低很多）
                    suffixes = [suffix for suffix in local_hash if
                                local_hash[suffix] !=
                                remote_hash.get(suffix, -1)]
					#同步最新验证过的不一致的hash后缀目录（sync根据所配置的模块进行调用）
                    self.sync(node, job, suffixes)
                    with Timeout(self.http_timeout):
                        conn = http_connect(
                            node['replication_ip'], node['replication_port'],
                            node['device'], job['partition'], 'REPLICATE',
                            '/' + '-'.join(suffixes),
                            headers=self.headers)
                        conn.getresponse().read()
                    self.suffix_sync += len(suffixes)
                    self.logger.update_stats('suffix.syncs', len(suffixes))
                except (Exception, Timeout):
                    self.logger.exception(_("Error syncing with node: %s") %
                                          node)
            self.suffix_count += len(local_hash)
        except (Exception, Timeout):
            self.logger.exception(_("Error syncing partition"))
        finally:
            self.partition_times.append(time.time() - begin)
            self.logger.timing_since('partition.update.timing', begin)