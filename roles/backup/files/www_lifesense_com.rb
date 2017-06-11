# encoding: utf-8


Model.new(:www_lifesense_com, 'Description for www_lifesense_com') do

  archive :my_archive do |archive|
    # Run the `tar` command using `sudo`
    # archive.use_sudo
    archive.add "/data/lifesense/www"
    archive.add "/data/apps/nginx/conf/vhost/static.lifesense.com.conf"
    archive.add "/data/apps/nginx/conf/vhost/www.lifesense.com.conf"
    archive.exclude "/data/lifesense/www/Cache/Runtime/Home/Logs"
  end

  database MySQL do |db|
    # To dump all databases, set `db.name = :all` (or leave blank)
    db.name               = "lifesense"
    db.username           = "lifesense"
    db.password           = "eGCidES9MkpNvv2a"
    db.host               = "10.10.95.39"
    db.port               = 3306
    # Note: when using `skip_tables` with the `db.name = :all` option,
    # table names should be prefixed with a database name.
    # e.g. ["db_name.table_to_skip", ...]
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
    local.keep       = 30
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
