from rolekit.server.io.systemd import SystemdContainerServiceUnit

img = 'testimage'
cont = 'testcontainer'
desc = 'this test container'
env = {'var_y': 'value_y', 'var_x': 'value_x'}
ports = [8080, 443]

s = SystemdContainerServiceUnit(image_name=img, container_name=cont, desc=desc, env=env, ports=ports)
s.write()
