from osmclient import client


class OSM:

    def __init__(self,
                 hostname='127.0.0.1',
                 sol005=True,
                 user=None,
                 password=None,
                 project=None,
                 so_port=None,
                 so_project=None,
                 ro_hostname=None,
                 ro_port=None):
        self.hostname = hostname
        self.sol005 = sol005
        self.kwargs = {}
        if so_port is not None:
            self.kwargs['so_port'] = so_port
        if so_project is not None:
            self.kwargs['so_project'] = so_project
        if ro_hostname is not None:
            self.kwargs['ro_host'] = ro_hostname
        if ro_port is not None:
            self.kwargs['ro_port'] = ro_port
        if user is not None:
            self.kwargs['user'] = user
        if password is not None:
            self.kwargs['password'] = password
        if project is not None:
            self.kwargs['project'] = project

    def get_osm_client(self):
        return client.Client(host=self.hostname,
                             sol005=self.sol005,
                             **self.kwargs)
