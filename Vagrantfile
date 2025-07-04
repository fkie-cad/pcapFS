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

  # Fedora boxes
  config.vm.define "fedora-37" do |fedora37|
    fedora37.vm.box = "bento/fedora-37"
  end
  config.vm.define "fedora-38" do |fedora38|
    fedora38.vm.box = "bento/fedora-38"
  end
  config.vm.define "fedora-39" do |fedora39|
    fedora39.vm.box = "bento/fedora-39"
  end
  config.vm.define "fedora-40" do |fedora40|
    fedora40.vm.box = "bento/fedora-40"
  end
  config.vm.define "fedora-41" do |fedora41|
    fedora41.vm.box = "bento/fedora-41"
  end

  # Kali boxes
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
  end

  # Ubuntu boxes
  config.vm.define "ubuntu-20.04" do |focal|
    focal.vm.box = "ubuntu/focal64"
  end
  config.vm.define "ubuntu-22.04" do |jammy|
      jammy.vm.box = "ubuntu/jammy64"
  end
  config.vm.define "ubuntu-24.04" do |jammy|
    jammy.vm.box = "bento/ubuntu-24.04"
  end

  # Debian boxes
  config.vm.define "debian-11" do |bullseye|
    bullseye.vm.box = "debian/bullseye64"
  end
  config.vm.define "debian-12" do |bookworm|
    bookworm.vm.box = "debian/bookworm64"
  end

  # CentOS boxes
  config.vm.define "centos-9" do |centos9|
    centos9.vm.box = "centos/stream9"
  end
  config.vm.define "centos-10" do |centos10|
    centos10.vm.box = "centos/stream10"
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
