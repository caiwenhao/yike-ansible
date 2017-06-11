JAVA_HOME="${CATALINA_HOME}/../deps/{{jdk_version}}/"
{% if jdk_version == "jdk1.7.0_79" %}
JAVA_OPTS="-server -Xms2048m -Xmx2048m -Xss1m -XX:PermSize=2048m -XX:MaxPermSize=2048m -Duser.timezone=Asia/Shanghai -Dfile.encoding=UTF-8"
{% else %}
JAVA_OPTS="-server -Xms2048m -Xmx2048m -Xss1m -XX:MetaspaceSize=1024m -XX:MaxMetaspaceSize=1024m -Duser.timezone=Asia/Shanghai -Dfile.encoding=UTF-8"
{% endif %}
CATALINA_OPTS="-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -Djava.rmi.server.hostname=127.0.0.1 -Djava.library.path=/data/apps/deps/apr/lib -Djetty.home=/data/web"
