# TODO: rename vmware_tag to just tag, for `vmware.tag` (also the filename is irrelvant for salt's loader, so...) -W. Werner, 2021-04-12
import saltext.vmware.modules.vmware_tag as tag
"""
These are high-level "thin red line" tests for the module. Essentially, they
can be run against a configured vCenter instance to ensure that from a high
level, functionality has not been destroyed. These tests may take a longer
time to run. Completeness is more important than granularity. In other words,
if a test fails here we may not know exactly why, but any bug that is released
must have an accompanying test here to expose that bug.
"""


def test_this_needs_to_be_changed(service_instance):
    # This is not a real test - we're not using our extension at all.
    # But it *does* use the service_instance with a config, so... bonus!
    expected_name = "tinyboi"
    root_folder = service_instance.RetrieveContent().rootFolder
    view = service_instance.content.viewManager.CreateContainerView(root_folder, recursive=True)
    names = [item.name for item in view.view]

    assert expected_name in names


# Okay, another informative thing - create/update/delete tags. Um... yeah I
# think all of that makes sense. Currently we only have a create tag. I'm not
# sure how update tag should work... I do know how to actually update a tag
# though!

# Hrm. Well, let's see what we can do with what we have already here in this
# port...


def test_tagalong(vsphere_client):
    #tags = tag.list_tags(service_instance=service_instance)
    # interesting - there's also https://github.com/vmware/vsphere-automation-sdk-python
    #root_folder = service_instance.RetrieveContent().rootFolder
    #view = service_instance.content.viewManager.CreateContainerView(root_folder, recursive=True)
    #uuid = None
    #for i in view.view:
    #    if i.name == 'tinyboi':
    #        breakpoint()
    #        uuid = i.uuid
    #breakpoint()
    tags = client.tagging.Tag.list()
    breakpoint()
    assert False
