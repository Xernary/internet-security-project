#!/bin/bash

# DEPENDENCIES
apt update
apt install sudo vim curl iproute2 procps unzip sed

#------------------

# SERVER SETUP

# ORACLE
cd
curl -O https://repo.huaweicloud.com/java/jdk/8u171-b11/jdk-8u171-linux-x64.tar.gz
cp jdk-8u171-linux-x64.tar.gz /tmp
cd /tmp
tar -xvf jdk-8u171-linux-x64.tar.gz
sudo mkdir -p /usr/lib/jvm
sudo mv ./jdk1.8.0* /usr/lib/jvm/
sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_171/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_171/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_171/bin/javaws" 1
sudo chmod a+x /usr/bin/java
sudo chmod a+x /usr/bin/javac
sudo chmod a+x /usr/bin/javaws
sudo chown -R root:root /usr/lib/jvm/jdk1.8.0_171
sudo update-alternatives --config java
sudo update-alternatives --config javac
sudo update-alternatives --config javaws

# TOMCAT
cd
curl -O https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.0.M26/bin/apache-tomcat-9.0.0.M26.tar.gz
tar xvzf apache-tomcat-9.0.0.M26.tar.gz
sudo mkdir /usr/local/tomcat
sudo mv apache-tomcat-9.0.0.M26/* /usr/local/tomcat
cd
echo 'export JAVA_HOME=/usr/lib/jvm/jdk1.8.0_171' >> .bashrc
source .bashrc
sudo echo -e "#!/bin/bash \n/usr/local/tomcat/bin/startup.sh\nexit 0" > /etc/rc.local
sudo chmod a+x /etc/rc.local
sudo ln -s /usr/local/tomcat/bin/startup.sh ./startup.sh
chmod a+x ./startup.sh 
./startup.sh

# STRUTS2 (vulnerable version)
cd
curl -O http://archive.apache.org/dist/struts/2.5.10/struts-2.5.10-all.zip
unzip struts-2.5.10-all.zip
mv struts-2.5.10 struts2

# MAVEN
cd /tmp
curl -O https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.5.0/apache-maven-3.5.0-bin.tar.gz
sudo tar xvzf apache-maven*.tar.gz -C /opt/
cd
echo 'export PATH=$PATH:/opt/apache-maven-3.5.0/bin' >> .bashrc
source .bashrc
cd
mvn archetype:generate \
-DgroupId=com.tutorialforlinux \
-DartifactId=myWebApp \
-DarchetypeArtifactId=maven-archetype-webapp
# at the message "Define value for property 'version' 1.0-SNAPSHOT: :" press Enter
# at the message "Y: :" press Enter
cd myWebApp
sed -i 's|<finalName>myWebApp</finalName>|<finalName>basic_struts</finalName>|' "pom.xml"
sed -i '/<\/dependencies>/i \
    <dependency>\
      <groupId>org.apache.struts</groupId>\
      <artifactId>struts2-core</artifactId>\
      <version>2.5.10</version>\
    </dependency>' "pom.xlm"
mvn clean package

# CONFIGURING AND DEPLOYING WEB APP
cd 
echo 'export CATALINA_HOME=/usr/local/tomcat' >> .bashrc
source .bashrc
cd $CATALINA_HOME
sed -i '/<\/tomcat-users>/i \
  <role rolename="manager-gui" />\
  <user username="admin" password="admin" roles="manager-gui"/>' "conf/tomcat-users.xml"
sudo touch $CATALINA_HOME/conf/Catalina/localhost/manager.xml
echo '<Context privileged="true" antiResourceLocking="false"
docBase="${catalina.home}/webapps/manager">
<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="^.*$" />
</Context>' > $CATALINA_HOME/conf/Catalina/localhost/manager.xml
sudo $CATALINA_HOME/bin/shutdown.sh
sudo $CATALINA_HOME/bin/startup.sh
# On the host machine download the vulnerable App (.war file) from:
# https://github.com/nixawk/labs/blob/master/CVE-2017-5638/struts2_2.3.15.1-showcase.war
#
# From the host machine go to http://IP:8080/manager and enter the following credentials:
# Username: admin
# Password: admin
#
# Scroll to the Deploy section and select the downloaded .war file

















