# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end
  #config.vm.synced_folder "../../", "/pcap/"
  #config.vm.provision "shell", "path": "scripts/vagrant/provision.sh"
  $provision_script = <<-PROVISION_SCRIPT
  mkdir pcapfs
  (cd /vagrant && tar -cf - \
    --exclude=./3rdparty \
    --exclude=./build \
    --exclude=./cmake-build-debug \
    --exclude=./dependencies \
    --exclude=.git \
    --exclude=.vagrant .) | tar -C pcapfs -xf -
  PROVISION_SCRIPT

  config.vm.provision "shell", inline: $provision_script

  # CentOS boxes
  config.vm.define "centos-6" do |centos6|
    centos6.vm.box = "bento/centos-6"
  end
  config.vm.define "centos-7" do |centos7|
    centos7.vm.box = "bento/centos-7"
  end

  # Ubuntu boxes
  config.vm.define "ubuntu-14.04" do |trusty|
    trusty.vm.box = "ubuntu/trusty64"
  end
  config.vm.define "ubuntu-16.04" do |xenial|
    xenial.vm.box = "ubuntu/xenial64"
  end
  config.vm.define "ubuntu-18.04" do |bionic|
    bionic.vm.box = "ubuntu/bionic64"
  end

  if Vagrant.has_plugin?("vagrant-proxyconf")
    if ENV["http_proxy"]
      config.proxy.http = ENV["http_proxy"]
    end
    if ENV["https_proxy"]
      config.proxy.https = ENV["https_proxy"]
    end
    if ENV["no_proxy"]
      config.proxy.no_proxy = ENV["no_proxy"]
    end
  end

end
