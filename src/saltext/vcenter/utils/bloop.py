import ssl

from pyVim import connect
from pyVmomi import vim


HOSTY_HOST = "10.206.240.183"
NAMY_NAME = "tinyboi"


def voom():
    ctx = ssl._create_unverified_context()
    si = connect.SmartConnect(host=HOSTY_HOST, user="root", pwd="VMware1!", sslContext=ctx)
    f = si.RetrieveContent().rootFolder
    v = si.content.viewManager.CreateContainerView(f, recursive=True)

    for item in v.view:
        if item.name == NAMY_NAME:
            thing = item
    return str(thing.storage)
