# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.gui = false
  end
  config.vm.provision "shell", "path": "scripts/vagrant/provision.sh"

  # CentOS boxes
  config.vm.define "centos-7" do |centos7|
    centos7.vm.box = "bento/centos-7"
  end

  # Kali boxes
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
  end

  # Ubuntu boxes
  config.vm.define "ubuntu-16.04" do |xenial|
    xenial.vm.box = "ubuntu/xenial64"
  end
  config.vm.define "ubuntu-18.04" do |bionic|
    bionic.vm.box = "ubuntu/bionic64"
  end
  config.vm.define "ubuntu-20.04" do |focal|
    focal.vm.box = "ubuntu/focal64"
  end
  config.vm.define "ubuntu-22.04" do |jammy|
      jammy.vm.box = "ubuntu/jammy64"
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
