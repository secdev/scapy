Netflow
=======

Netflow packets mainly comes in 3 versions::

- ``Netflow V5``
- ``Netflow V7``
- ``Netflow V9 / V10 (IPfix)``

While the two first versions are pretty straightforward, building or dissecting Netflow v9/v10 isn't easy.

Netflow V1
----------

.. code::

    netflow = NetflowHeader()/NetflowHeaderV1()/NetflowRecordV1()
    pkt = Ether()/IP()/UDP()/netflow

Netflow V5
----------

.. code::

    netflow = NetflowHeader()/NetflowHeaderV5(count=1)/NetflowRecordV5(dst="192.168.0.1")
    pkt = Ether()/IP()/UDP()/netflow

NetflowV9 / IPfix
-----------------

Netflow v9 and IPfix use a template based system. This means that records that are sent over the wire require a "Template" to be sent previously in a Flowset packet.

This template is required to understand thr format of the record, therefore needs to be provided when building or dissecting those.

Fortunately, Scapy knows how to detect the templates and will provide dissecting methods that take care of that.

.. note::

    The following examples apply to Netflow V9. When using IPfix, use the exact same format but replace the class names with their V10 counterpart (if they exist ! Scapy shares some classes between the two). Have a look at :mod:`~scapy.layers.netflow`

- **Build**

.. code::

    header = Ether()/IP()/UDP()
    netflow_header = NetflowHeader()/NetflowHeaderV9()

    # Let's first build the template. Those need an ID > 255.
    # The (full) list of possible fieldType is available in the
    # NetflowV910TemplateFieldTypes list. You can also use the int value.
    flowset = NetflowFlowsetV9(
        templates=[NetflowTemplateV9(
            template_fields=[
                NetflowTemplateFieldV9(fieldType="IN_BYTES", fieldLength=1),
                NetflowTemplateFieldV9(fieldType="IN_PKTS", fieldLength=4),
                NetflowTemplateFieldV9(fieldType="PROTOCOL"),
                NetflowTemplateFieldV9(fieldType="IPV4_SRC_ADDR"),
                NetflowTemplateFieldV9(fieldType="IPV4_DST_ADDR"),
            ],
            templateID=256,
            fieldCount=5)
        ],
        flowSetID=0
    )
    # Let's generate the record class. This will be a Packet class
    # In case you provided several templates in ghe flowset, you will need
    # to pass the template ID as second parameter
    recordClass = GetNetflowRecordV9(flowset)
    # Now lets build the data records
    dataFS = NetflowDataflowsetV9(
        templateID=256,
        records=[ # Some random data.
            recordClass(
                IN_BYTES=b"\x12",
                IN_PKTS=b"\0\0\0\0",
                PROTOCOL=6,
                IPV4_SRC_ADDR="192.168.0.10",
                IPV4_DST_ADDR="192.168.0.11"
            ),
            recordClass(
                IN_BYTES=b"\x0c",
                IN_PKTS=b"\1\1\1\1",
                PROTOCOL=3,
                IPV4_SRC_ADDR="172.0.0.10",
                IPV4_DST_ADDR="172.0.0.11"
            )
        ],
    )
    pkt = header / netflow_header / flowset / dataFS

- **Dissection**

Scapy provides two methods to parse NetflowV9/IPFix:

- :class:`~scapy.layers.netflow.NetflowSession`: to use with ``sniff(session=NetflowV9Session, [...])``
- :func:`~scapy.layers.netflow.netflowv9_defragment`: to use on a packet or list of packets.

With the previous example::

    pkt = Ether(raw(pkt))  # will loose the defragmentation
    pkt = netflowv9_defragment(pkt)[0]
