#!/bin/bash -x

dnf remove -y fedora-release-cloud
rm -f /usr/lib/os-release /etc/firewalld/firewalld.conf
dnf install -y fedora-release-server

dnf install -y @buildsys-build rolekit libxslt graphviz polkit rng-tools

dnf builddep -y /vagrant/rolekit.spec

hostnamectl set-hostname vagrant.rolekit.lan

cat << EOF >> /home/vagrant/.bashrc
source /usr/share/git-core/contrib/completion/git-prompt.sh
export GIT_PS1_SHOWDIRTYSTATE=1
export PS1='[\u@\h:\W\$(__git_ps1 " (%s)")]\$\[\e[0m\] '
EOF

RK_ARCH=$(uname -m)
RK_LIBDIR=$(rpm --eval %{_libdir})

pushd /vagrant
make distclean
su vagrant -c "./autogen.sh \
        --build=$RK_ARCH-unknown-linux-gnu \
        --host=$RK_ARCH-unknown-linux-gnu \
        --program-prefix= \
        --prefix=/usr \
        --exec-prefix=/usr \
        --bindir=/usr/bin \
        --sbindir=/usr/sbin \
        --sysconfdir=/etc \
        --datadir=/usr/share \
        --includedir=/usr/include \
        --libdir=$RK_LIBDIR \
        --libexecdir=/usr/libexec \
        --localstatedir=/var \
        --sharedstatedir=/var/lib \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info"

if [ -e rolekit.spec.pre-provision ]; then
    mv rolekit.spec.pre-provision rolekit.spec
fi

sed -i.pre-provision -e "s/{?dist}/{?dist}.`date -u +%Y.%m.%d.%H%M.%S`/" rolekit.spec

rm -Rf /home/vagrant/rpmbuild/RPMS/noarch
su vagrant -c "make test-rpm"
dnf -y install /home/vagrant/rpmbuild/RPMS/noarch/*.rpm

systemctl daemon-reload
systemctl enable firewalld.service
systemctl restart firewalld.service
systemctl enable rolekit.service
systemctl restart rolekit.service

# Use the non-blocking random pool
/usr/sbin/rngd -r /dev/urandom
