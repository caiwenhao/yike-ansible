# encoding: utf-8


Model.new(:dataweb_lifesense_com, 'Description for dataweb_lifesense_com') do

  archive :my_archive do |archive|
    archive.add "/data/apps/phpredmin1"
    archive.add "/data/apps/phpredmin"
    archive.add "/data/apps/KafkaOffsetMonitor_logs/KafkaOffsetMonitor-assembly-0.2.1.jar"
    archive.add "/data/apps/KafkaOffsetMonitor_logs/start.sh"
    archive.add "/data/apps/KafkaOffsetMonitor_online/KafkaOffsetMonitor-assembly-0.2.1.jar"
    archive.add "/data/apps/KafkaOffsetMonitor_online/start.sh"
    archive.add "/data/apps/KafkaOffsetMonitor_qa/KafkaOffsetMonitor-assembly-0.2.1.jar"
    archive.add "/data/apps/KafkaOffsetMonitor_qa/start.sh"
    archive.add "/data/apps/nginx/conf/vhost/"
    archive.add "/data/www"
    archive.add "/data/ldap"
  end

  store_with FTP do |server|
    server.username     = 'backup'
    server.password     = 'rCBsCAMgzBKyLDKc'
    server.ip           = '10.10.157.234'
    server.port         = 21
    server.path         = '~/'
    server.keep         = 30
    server.passive_mode = false
    server.timeout      = 10
  end

  store_with Local do |local|
    local.path       = "/data/Backup/backups/"
    local.keep       = 5
    local.keep       = Time.now - 2592000 # Remove all backups older than 1 month.
  end

  encrypt_with OpenSSL do |encryption|
    encryption.password      = "lifesense!@#_backup"            # From String
    encryption.base64        = true
    encryption.salt          = true
  end

  compress_with Gzip

  notify_by Zabbix do |zabbix|
    zabbix.on_success = true
    zabbix.on_warning = true
    zabbix.on_failure = true

    zabbix.zabbix_host  = "10.10.89.24"
    zabbix.zabbix_port  = 30051
    zabbix.service_name = "backup_status"
    zabbix.service_host = "lx-yw-backup-10.10.157.234-22-B0"
    zabbix.item_key     = "backup_status"
  end

end
