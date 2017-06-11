# encoding: utf-8


Model.new(:zabbix_lifesense_com, 'Description for zabbix_lifesense_com') do

  archive :my_archive do |archive|
    archive.add "/data/apps/zabbix-3.0.1"
    archive.add "/etc/init.d/zabbix_server"
    archive.add "/data/apps/nginx/conf/vhost/zabbix.conf"
  end

  database MySQL do |db|
    # To dump all databases, set `db.name = :all` (or leave blank)
    db.name               = "zabbix"
    db.username           = "zabbix"
    db.password           = "!@#zabbix!@#"
    db.host               = "10.10.177.44"
    db.port               = 3306
    db.skip_tables        = ["history", "history_uint"]
    db.additional_options = ["--quick", "--single-transaction"]
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
