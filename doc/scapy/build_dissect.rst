********************
Adding new protocols
********************

Adding new protocol (or more correctly: a new *layer*) in Scapy is very easy. All the magic is in the fields. If the 
fields you need are already there and the protocol is not too brain-damaged, 
this should be a matter of minutes. 

Simple example
==============

A layer is a subclass of the ``Packet`` class. All the logic behind layer manipulation 
is hold by the ``Packet`` class and will be inherited. 
A simple layer is compounded by a list of fields that will be either concatenated 
when assembling the layer or dissected one by one when disassembling a string. 
The list of fields is held in an attribute named ``fields_desc``. Each field is an instance 
of a field class:: 

    class Disney(Packet): 
        name = "DisneyPacket " 
        fields_desc=[ ShortField("mickey",5), 
                     XByteField("minnie",3) , 
                     IntEnumField("donald" , 1 , 
                          { 1: "happy", 2: "cool" , 3: "angry" } ) ]
                       
In this example, our layer has three fields. The first one is an 2 byte integer 
field named ``mickey`` and whose default value is 5. The second one is a 1 byte 
integer field named ``minnie`` and whose default value is 3. The difference between 
a vanilla ``ByteField`` and a ``XByteField`` is only the fact that the prefered human 
representation of the field’s value is in hexadecimal. The last field is a 4 byte 
integer field named ``donald``. It is different from a vanilla ``IntField`` by the fact 
that some of the possible values of the field have litterate representations. For 
example, if it is worth 3, the value will be displayed as angry. Moreover, if the 
"cool" value is assigned to this field, it will understand that it has to take the 
value 2. 

If your protocol is as simple as this, it is ready to use:: 

    >>> d=Disney(mickey=1) 
    >>> ls(d) 
    mickey : ShortField = 1 (5) 
    minnie : XByteField = 3 (3) 
    donald : IntEnumField = 1 (1) 
    >>> d.show() 
    ###[ Disney Packet ]### 
    mickey= 1 
    minnie= 0x3 
    donald= happy 
    >>> d.donald="cool" 
    >>> str(d) 
    ’\x00\x01\x03\x00\x00\x00\x02’ 
    >>> Disney( ) 
    <Disney mickey=1 minnie=0x3 donald=cool |> 


This chapter explains how to build a new protocol within Scapy. There are two main objectives:

* Dissecting: this is done when a packet is received (from the network or a file) and should be converted to Scapy’s internals.
* Building: When one wants to send such a new packet, some stuff needs to be adjusted automatically in it.

Layers
======

Before digging into dissection itself, let us look at how packets are
organized.

::

    >>> p = IP()/TCP()/"AAAA"
    >>> p
    <IP  frag=0 proto=TCP |<TCP  |<Raw  load='AAAA' |>>>
    >>> p.summary()
    'IP / TCP 127.0.0.1:ftp-data > 127.0.0.1:www S / Raw'

We are interested in 2 "inside" fields of the class ``Packet``:

* ``p.underlayer``
* ``p.payload``

And here  is the  main "trick".  You do not  care about  packets, only
about layers, stacked one after the other. 

One can easily  access a layer by its name: ``p[TCP]`` returns the ``TCP``
and followings layers. This is a shortcut for ``p.getlayer(TCP)``.

.. note::
   There is  an optional argument (``nb``) which returns  the ``nb`` th  layer of required protocol.

Let's put everything together now, playing with the ``TCP`` layer::

    >>> tcp=p[TCP]
    >>> tcp.underlayer
    <IP  frag=0 proto=TCP |<TCP  |<Raw  load='AAAA' |>>>
    >>> tcp.payload
    <Raw  load='AAAA' |>

As expected, ``tcp.underlayer`` points to the beginning of our IP packet,
and ``tcp.payload`` to its payload.

Building a new layer
--------------------

.. index::
   single: Layer

VERY EASY! A layer is mainly a list of fields. Let's look at ``UDP`` definition::

    class UDP(Packet):
        name = "UDP"
        fields_desc = [ ShortEnumField("sport", 53, UDP_SERVICES),
                        ShortEnumField("dport", 53, UDP_SERVICES),
                        ShortField("len", None),
                        XShortField("chksum", None), ]

And you are done! There are many fields already defined for
convenience, look at the doc``^W`` sources as Phil would say.

So, defining a layer is simply gathering fields in a list. The goal is
here to  provide the  efficient default values  for each field  so the
user does not have to give them when he builds a packet. 

The main  mechanism  is based on  the ``Field`` structure.  Always keep in
mind that a layer is just a little more than a list of fields, but not
much more. 

So, to understanding how layers are working, one needs to look quickly
at how the fields are handled.


Manipulating packets == manipulating its fields
-----------------------------------------------

.. index::
   single: i2h()
   single: i2m()
   single: m2i()

A field should be considered in different states:

- ``i`` (nternal) : this is the way Scapy manipulates it.
- ``m`` (achine) : this is where the truth is, that is the layer as it is
    on the network.
- ``h`` (uman) : how the packet is displayed to our human eyes.

This explains  the mysterious  methods ``i2h()``, ``i2m()``,  ``m2i()`` and  so on
available  in  each field:  they are conversion  from one  state  to
another, adapted to a specific use.

Other special functions:

- ``any2i()`` guess the input representation and returns the internal one.
- ``i2repr()`` a nicer ``i2h()``

However, all these are "low level" functions. The functions adding or
extracting a field to the current layer are:

- ``addfield(self, pkt, s, val)``:  copy the network  representation of
  field ``val`` (belonging to layer ``pkt``) to the raw string packet ``s``::

      class StrFixedLenField(StrField):
          def addfield(self, pkt, s, val):
              return s+struct.pack("%is"%self.length,self.i2m(pkt, val))

- ``getfield(self, pkt, s)``: extract from the raw packet ``s`` the field
  value belonging to layer ``pkt``. It returns a list, the 1st element
  is the raw packet string after having removed the extracted field,
  the second one is the extracted field itself in internal
  representation::

      class StrFixedLenField(StrField):
          def getfield(self, pkt, s):
              return s[self.length:], self.m2i(pkt,s[:self.length])
       
When defining your own layer, you usually just need to define some
``*2*()`` methods, and sometimes also the ``addfield()`` and ``getfield()``.


Example: variable length quantities
-----------------------------------

There is way to represent integers on a variable length quantity often
used in  protocols, for instance  when dealing with  signal processing
(e.g. MIDI). 

Each byte  of the number is  coded with the  MSB set to 1,  except the
last byte. For instance, 0x123456 will be coded as 0xC8E856:: 

    def vlenq2str(l):
        s = []
        s.append( hex(l & 0x7F) )
        l = l >> 7
        while l>0:
            s.append( hex(0x80 | (l & 0x7F) ) )
            l = l >> 7
        s.reverse()
        return "".join(map( lambda(x) : chr(int(x, 16)) , s))
    
    def str2vlenq(s=""):
        i = l = 0
        while i<len(s) and ord(s[i]) & 0x80:
            l = l << 7
            l = l + (ord(s[i]) & 0x7F)
            i = i + 1
        if i == len(s):
            warning("Broken vlenq: no ending byte")
        l = l << 7
        l = l + (ord(s[i]) & 0x7F)
    
        return s[i+1:], l

We will  define a field which  computes automatically the  length of a
associated string, but used that encoding format::

    class VarLenQField(Field):
        """ variable length quantities """
    
        def __init__(self, name, default, fld):
            Field.__init__(self, name, default)
            self.fld = fld
            
        def i2m(self, pkt, x):
            if x is None:
                f = pkt.get_field(self.fld)
                x = f.i2len(pkt, pkt.getfieldval(self.fld))
                x = vlenq2str(x)
            return str(x)
    
        def m2i(self, pkt, x):
            if s is None:
                return None, 0
            return str2vlenq(x)[1]
    
        def addfield(self, pkt, s, val):
            return s+self.i2m(pkt, val)
    
        def getfield(self, pkt, s):
            return str2vlenq(s)

And now, define a layer using this kind of field::

    class FOO(Packet):
        name = "FOO"
        fields_desc = [ VarLenQField("len", None, "data"),
                        StrLenField("data", "", "len") ]
    
        >>> f = FOO(data="A"*129)
        >>> f.show()
        ###[ FOO ]###
          len= 0
          data=    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

Here, ``len``  is  not  yet  computed  and only  the  default  value  are
displayed.  This  is  the   current  internal  representation  of  our
layer. Let's force the computation now::

    >>> f.show2()
    ###[ FOO ]###
      len= 129
      data= 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

The method ``show2()`` displays the  fields with their values as they will
be sent to the network, but in a human readable way, so we see ``len=129``.
Last but not least, let us look now at the machine representation::

    >>> str(f)
    '\x81\x01AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

The first 2 bytes are ``\x81\x01``, which is 129 in this encoding.


 
Dissecting 
==========
.. index::
   dissecting
   
Layers are  only list  of fields,  but what is  the glue  between each
field, and after, between each  layer. These are the mysteries explain
in this section.

The basic stuff
---------------

The core function for dissection is ``Packet.dissect()``::

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)            
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))

When called, ``s`` is a string containing what is going to be
dissected. ``self`` points to the current layer.
 
::

    >>> p=IP("A"*20)/TCP("B"*32)
    WARNING: bad dataofs (4). Assuming dataofs=5
    >>> p
    <IP  version=4L ihl=1L tos=0x41 len=16705 id=16705 flags=DF frag=321L ttl=65 proto=65 chksum=0x4141
    src=65.65.65.65 dst=65.65.65.65 |<TCP  sport=16962 dport=16962 seq=1111638594L ack=1111638594L dataofs=4L
    reserved=2L flags=SE window=16962 chksum=0x4242 urgptr=16962 options=[] |<Raw  load='BBBBBBBBBBBB' |>>>

``Packet.dissect()`` is called 3 times:

1. to dissect the ``"A"*20`` as an IPv4 header
2. to dissect the ``"B"*32`` as a TCP header
3. and  since  there  are still  12  bytes  in  the packet,  they  are
   dissected as "``Raw``" data (which is some kind of default layer type)


For a given layer, everything is quite straightforward:

- ``pre_dissect()`` is called to prepare the layer.
- ``do_dissect()`` perform the real dissection of the layer.
- ``post_dissection()`` is  called when some  updates are needed  on the
  dissected inputs (e.g. deciphering, uncompressing, ... )
- ``extract_padding()`` is an important  function which should be called
  by every  layer containing  its own size, so that it can tell apart 
  in  the payload what is really related to this layer and what will
  be considered as additional padding bytes.
- ``do_dissect_payload()``  is the  function in  charge of  dissecting the
  payload  (if  any).  It   is  based  on  ``guess_payload_class()``  (see
  below). Once the type of the  payload is known, the payload is bound
  to the current layer with this new type::

      def do_dissect_payload(self, s):
          cls = self.guess_payload_class(s)
          p = cls(s, _internal=1, _underlayer=self)
          self.add_payload(p)

At the  end, all  the layers  in the packet  are dissected,  and glued
together with their known types.


Dissecting fields
-----------------

The  method with  all the  magic  between a  layer and  its fields  is
``do_dissect()``. If you have  understood the different representations of
a layer, you  should understand that "dissecting" a  layer is building
each of its fields from the machine to the internal representation. 

Guess what? That is exactly what ``do_dissect()`` does::

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f] = fval
        return s

So, it  takes the raw string packet,  and feed each field  with it, as
long as there are data or fields remaining::

    >>> FOO("\xff\xff"+"B"*8)
    <FOO  len=2097090 data='BBBBBBB' |>

When writing ``FOO("\xff\xff"+"B"*8)``, it calls ``do_dissect()``. The first
field is VarLenQField.  Thus, it takes bytes as long as their MSB is
set, thus until (and including) the first '``B``'. This mapping is done
thanks to ``VarLenQField.getfield()`` and can be cross-checked::

    >>> vlenq2str(2097090)
    '\xff\xffB'

Then, the  next field is extracted  the same way, until 2097090 bytes
are put in ``FOO.data`` (or less  if 2097090 bytes are  not available, as
here).

If  there are  some bytes  left after  the dissection  of  the current
layer, it is mapped  in the same way to the what  the next is expected
to be (``Raw`` by default)::

    >>> FOO("\x05"+"B"*8)
    <FOO  len=5 data='BBBBB' |<Raw  load='BBB' |>>

Hence, we need now to understand how layers are bound together.

Binding layers
--------------

One of the cool features with  Scapy when dissecting layers is that is
try to guess for us what the next layer is. The official way to link 2
layers is using ``bind_layers()``:

For instance,  if you have a class ``HTTP``, you may expect  that all the
packets coming from or going to  port 80 will be decoded as such. This
is simply done that way::

    bind_layers( TCP, HTTP, sport=80 )
    bind_layers( TCP, HTTP, dport=80 )

That's  all folks!  Now every  packet  related to  port  80 will  be
associated to the  layer ``HTTP``, whether it is read from  a pcap file or
received from the network.

The ``guess_payload_class()`` way
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sometimes,  guessing the payload  class is  not as  straightforward as
defining a single  port. For instance, it can depends on  a value of a
given byte in the current layer. The 2 needed methods are:

- ``guess_payload_class()`` which must return  the guessed class for the
  payload (next layer). By default, it uses links between classes
  that have been put in place by ``bind_layers()``.

- ``default_payload_class()``  which returns  the  default value.   This
  method  defined in the  class ``Packet``  returns ``Raw``,  but it  can be
  overloaded.

For  instance, decoding  802.11  changes depending  on  whether it  is
ciphered or not::

    class Dot11(Packet):
        def guess_payload_class(self, payload):
            if self.FCfield & 0x40:
                return Dot11WEP
            else:
                return Packet.guess_payload_class(self, payload)

Several comments are needed here:

- this  cannot be  done  using  ``bind_layers()``  because the  tests  are
  supposed to be "``field==value``", but it is more complicated here as we
  test a single bit in the value of a field.
  
- if the  test fails, no assumption is  made, and we plug  back to the
  default guessing mechanisms calling ``Packet.guess_payload_class()``

Most of  the time,  defining a method  ``guess_payload_class()`` is  not a
necessity as the same result can be obtained from ``bind_layers()``.

Changing the default behavior
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you do not like Scapy's  behavior for a given layer, you can either
change or disable it through  the call to ``split_layer()``. For instance,
if you do not want UDP/53 to be bound with ``DNS``, just add in your code:
``
split_layers(UDP, DNS, sport=53)
``
Now every packet  with source port 53 will not be  handled as DNS, but
whatever you specify instead.



Under the hood: putting everything together
-------------------------------------------

In  fact, each  layer  has a  field  payload_guess. When  you use  the
bind_layers() way, it adds the defined next layers to that list.

::

    >>> p=TCP()
    >>> p.payload_guess
    [({'dport': 2000}, <class 'scapy.Skinny'>), ({'sport': 2000}, <class 'scapy.Skinny'>), ... )]

Then,  when it  needs to  guess  the next  layer class,  it calls  the
default method ``Packet.guess_payload_class()``.  This method runs through
each  element  of  the   list  payload_guess,  each  element  being  a
tuple:

- the 1st value is a field to test (``'dport': 2000``)
- the 2nd value is the guessed class if it matches (``Skinny``)

So, the  default ``guess_payload_class()`` tries all element  in the list,
until  one   matches.  If  no   element  are  found,  it   then  calls
``default_payload_class()``. If you have redefined this method, then yours
is  called, otherwise,  the default  one is  called, and  ``Raw``  type is
returned. 

``Packet.guess_payload_class()``

- test what is in field ``guess_payload``
- call overloaded ``guess_payload_class()``


Building
========

Building a packet is as simple as building each layer. Then, some
magic happens to glue everything. Let's do magic then.

The basic stuff
---------------

First thing to  establish: what does "build" mean? As  we have seen, a
layer  can   be  represented  in  different   ways  (human,  internal,
machine). Building means going to the machine format.

Second thing to  understand is ''when'' a layer is  built. Answer is not
that obvious, but as soon  as you need the machine representation, the
layers are built: when the packet is dropped on the network or written
to a  file, when it  is converted as  a string, ...  In  fact, machine
representation  should be  regarded as  a big  string with  the layers
appended altogether.
 
::

    >>> p = IP()/TCP()
    >>> hexdump(p)
    0000 45 00 00 28 00 01 00 00 40 06 7C CD 7F 00 00 01 E..(....@.|..... 
    0010 7F 00 00 01 00 14 00 50 00 00 00 00 00 00 00 00 .......P........ 
    0020 50 02 20 00 91 7C 00 00 P. ..|.. 

Calling ``str()`` builds the packet:
  - non instanced fields are set to their default value
  - lengths are updated automatically
  - checksums are computed
  - and so on. 

In fact, using ``str()`` rather than  ``show2()`` or any other method is not a
random  choice  as  all   the  functions  building  the  packet  calls
``Packet.__str__()``. However, ``__str__()`` calls another method: ``build()``::

    def __str__(self):
        return self.__iter__().next().build()

What is important also to understand  is that usually, you do not care
about the machine  representation, that is why the  human and internal
representations are here. 

So, the  core method is ``build()``  (the code has been  shortened to keep
only the relevant parts)::

    def build(self,internal=0):
        pkt = self.do_build()
        pay = self.build_payload()
        p = self.post_build(pkt,pay)
        if not internal:
            pkt = self
            while pkt.haslayer(Padding):
                pkt = pkt.getlayer(Padding)
                p += pkt.load
                pkt = pkt.payload
        return p

So, it  starts by  building the current  layer, then the  payload, and
``post_build()``  is called  to update  some late  evaluated  fields (like
checksums). Last, the padding is added to the end of the packet. 

Of  course, building  a layer  is  the same  as building  each of  its
fields, and that is exactly what ``do_build()`` does.

Building fields
---------------

The building of each field of a layer is called in ``Packet.do_build()``::

    def do_build(self):
        p=""
        for f in self.fields_desc:
            p = f.addfield(self, p, self.getfieldval(f))
        return p

The  core function  to  build a  field  is ``addfield()``.   It takes  the
internal view of the  field and put it at the end  of ``p``. Usually, this
method calls  ``i2m()`` and returns something  like ``p.self.i2m(val)`` (where
``val=self.getfieldval(f)``).

If ``val`` is set, then ``i2m()`` is just a matter of formatting the value the
way it must  be. For instance, if a  byte is expected, ``struct.pack("B", val)``
is the right way to convert it.

However, things  are more complicated if  ``val`` is not set,  it means no
default  value was  provided  earlier,  and thus  the  field needs  to
compute some "stuff" right now or later. 

"Right now"  means thanks  to ``i2m()``, if  all pieces of  information is
available.  For instance,  if  you have  to  handle a  length until  a
certain delimiter. 

Ex: counting the length until a delimiter

::

    class XNumberField(FieldLenField):
    
        def __init__(self, name, default, sep="\r\n"):
            FieldLenField.__init__(self, name, default, fld)
            self.sep = sep
    
        def i2m(self, pkt, x):
            x = FieldLenField.i2m(self, pkt, x)
            return "%02x" % x
    
        def m2i(self, pkt, x):
            return int(x, 16)
    
        def addfield(self, pkt, s, val):
            return s+self.i2m(pkt, val)
    
        def getfield(self, pkt, s):
            sep = s.find(self.sep)
            return s[sep:], self.m2i(pkt, s[:sep])

In this example,  in ``i2m()``, if ``x`` has already a  value, it is converted
to its hexadecimal value. If no value is given, a length of "0" is
returned.

The glue is provided by ``Packet.do_build()`` which calls ``Field.addfield()``
for  each field in  the layer,  which in  turn calls  ``Field.i2m()``: the
layer is built IF a value was available.


Handling default values: ``post_build``
---------------------------------------

A default  value for a  given field is  sometimes either not  known or
impossible to compute when the  fields are put together. For instance,
if we used a ``XNumberField`` as  defined previously in a layer, we expect
it  to be set  to a  given value  when the  packet is  built. However,
nothing is returned by ``i2m()`` if it is not set. 

The answer to this problem is ``Packet.post_build()``. 

When  this method is  called, the  packet is  already built,  but some
fields still need  to be computed. This is  typically what is required
to compute checksums or lengths. In fact, this is required each time a
field's value depends on something which is not in the current 

So, let  us assume we  have a packet  with a ``XNumberField``, and  have a
look to its building process::

    class Foo(Packet):
          fields_desc = [
              ByteField("type", 0),
              XNumberField("len", None, "\r\n"),
              StrFixedLenField("sep", "\r\n", 2)
              ]
            
          def post_build(self, p, pay):
            if self.len is None and pay:
                l = len(pay)
                p = p[:1] + hex(l)[2:]+ p[2:]
            return p+pay

When ``post_build()`` is called, ``p``  is the current layer, ``pay`` the payload,
that is what has already been built. We want our length to be the full
length of the data put after  the separator, so we add its computation
in ``post_build()``. 

::

    >>> p = Foo()/("X"*32)
    >>> p.show2()
    ###[ Foo ]###
      type= 0
      len= 32
      sep= '\r\n'
    ###[ Raw ]###
         load= 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

``len`` is correctly computed now::

    >>> hexdump(str(p))
    0000   00 32 30 0D 0A 58 58 58  58 58 58 58 58 58 58 58   .20..XXXXXXXXXXX
    0010   58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58   XXXXXXXXXXXXXXXX
    0020   58 58 58 58 58                                     XXXXX

And the machine representation is the expected one.


Handling default values: automatic computation
----------------------------------------------

As we have previously seen, the dissection mechanism is built upon the
links between  the layers created  by the programmer. However,  it can
also be used during the building process.

In the  layer ``Foo()``, our  first byte is  the type, which  defines what
comes next, e.g. if ``type=0``, next layer is ``Bar0``, if it is 1, next layer
is  ``Bar1``,  and  so on.  We  would  like  then  this  field to  be  set
automatically according to what comes next.
 
::

    class Bar1(Packet):
        fields_desc = [
              IntField("val", 0),
              ]
    
    class Bar2(Packet):
        fields_desc = [
              IPField("addr", "127.0.0.1")
              ]

If we use  these classes with nothing else, we  will have trouble when
dissecting the  packets as nothing  binds Foo layer with  the multiple
``Bar*`` even when we explicitly build the packet through the call to
``show2()``::

    >>> p = Foo()/Bar1(val=1337)
    >>> p
    <Foo  |<Bar1  val=1337 |>>
    >>> p.show2()
    ###[ Foo ]###
      type= 0
      len= 4
      sep= '\r\n'
    ###[ Raw ]###
        load= '\x00\x00\x059'

Problems:
 
1. ``type`` is still  equal to 0 while we wanted  it to be automatically
   set to 1. We could of course have built ``p`` with ``p = Foo(type=1)/Bar0(val=1337)``
   but this is not very convenient.
   
2. the packet is badly dissected as ``Bar1`` is regarded as ``Raw``. This
   is because no links have been set between ``Foo()`` and ``Bar*()``.

In order to  understand what we should have done  to obtain the proper
behavior,  we must look  at how  the layers  are assembled.   When two
independent packets instances ``Foo()`` and ``Bar1(val=1337)`` are
compounded with the '/' operator, it results in a new packet where the
two previous instances are cloned  (i.e.  are now two distinct objects
structurally different, but holding the same values)::

    def __div__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self/Raw(load=other)

The right  hand side of the  operator becomes the payload  of the left
hand    side.    This    is    performed   through    the   call    to
``add_payload()``. Finally, the new packet is returned.

Note: we can observe that if  other isn't a ``Packet`` but a string,
the ``Raw``  class is instantiated to  form the payload.  Like in this
example::

    >>> IP()/"AAAA"
    <IP  |<Raw  load='AAAA' |>>

Well, what  ``add_payload()`` should implement? Just  a link between
two packets? Not only, in  our case this method will appropriately set
the correct value to ``type``.

Instinctively  we feel that  the upper  layer (the  right of  '/') can
gather the  values to set the fields  to the lower layer  (the left of
'/').  Like  previously explained, there is a  convenient mechanism to
specify  the  bindings in  both  directions  between two  neighbouring
layers.

Once again, these information must be provided to ``bind_layers()``,
which  will   internally  call  ``bind_top_down()``   in  charge  to
aggregate the fields to overload. In our case what we needs to specify
is::

    bind_layers( Foo, Bar1, {'type':1} )
    bind_layers( Foo, Bar2, {'type':2} )

Then, ``add_payload()``  iterates over the  ``overload_fields`` of
the upper packet (the payload), get the fields associated to the lower
packet (by its type) and insert them in ``overloaded_fields``.
 
For  now,   when  the   value  of  this   field  will   be  requested,
``getfieldval()``    will    return    the   value    inserted    in
``overloaded_fields``.

The fields are dispatched between three dictionaries:

- ``fields``: fields whose the value have been explicitly set, like
  ``pdst`` in TCP (``pdst='42'``)
- ``overloaded_fields``: overloaded fields
- ``default_fields``: all the fields with their default value (these fields 
    are initialized according to ``fields_desc`` by the constructor 
    by calling ``init_fields()`` ).

In the following code we can observe how a field is selected and its
value returned::

    def getfieldval(self, attr):
       for f in self.fields, self.overloaded_fields, self.default_fields:
           if f.has_key(attr):
               return f[attr]
       return self.payload.getfieldval(attr)

Fields  inserted  in  ``fields``  have  the  higher  priority,  then
``overloaded_fields``, then finally ``default_fields``.  Hence, if
the field ``type`` is set in ``overloaded_fields``, its value will
be returned instead of the value contained in ``default_fields``.


We are now able to understand all the magic behind it!

::

    >>> p = Foo()/Bar1(val=0x1337)
    >>> p
    <Foo  type=1 |<Bar1  val=4919 |>>
    >>> p.show()
    ###[ Foo ]###
      type= 1
      len= 4
      sep= '\r\n'
    ###[ Bar1 ]###
        val= 4919
        
Our 2 problems have been solved without us doing much: so good to be
lazy :)

Under the hood: putting everything together
-------------------------------------------

Last but not least, it is very useful to understand when each function
is called when a packet is built::

    >>> hexdump(str(p))
    Packet.str=Foo
    Packet.iter=Foo
    Packet.iter=Bar1
    Packet.build=Foo
    Packet.build=Bar1
    Packet.post_build=Bar1
    Packet.post_build=Foo

As you can see, it first runs through the list of each field, and then
build  them starting  from the  beginning. Once  all layers  have been
built, it then calls ``post_build()`` starting from the end.


Fields 
======

.. index::
   single: fields

Here's a list of fields that Scapy supports out of the box:     

Simple datatypes
----------------

Legend: 

- ``X`` - hexadecimal representation
- ``LE`` - little endian (default is big endian = network byte order)
- ``Signed`` - signed (default is unsigned)

::

    ByteField           
    XByteField    
    
    ShortField
    LEShortField
    XShortField
    
    X3BytesField        # three bytes (in hexad 
    
    IntField
    SignedIntField
    LEIntField
    LESignedIntField
    XIntField
    
    LongField       
    XLongField
    LELongField
    
    IEEEFloatField
    IEEEDoubleField 
    BCDFloatField       # binary coded decimal
    
    BitField
    XBitField
    
    BitFieldLenField    # BitField specifying a length (used in RTP)
    FlagsField          
    FloatField

Enumerations
------------

Possible field values are taken from a given enumeration (list, dictionary, ...)  
e.g.::

    ByteEnumField("code", 4, {1:"REQUEST",2:"RESPONSE",3:"SUCCESS",4:"FAILURE"})

::

    EnumField(name, default, enum, fmt = "H")
    CharEnumField
    BitEnumField
    ShortEnumField
    LEShortEnumField
    ByteEnumField
    IntEnumField
    SignedIntEnumField
    LEIntEnumField
    XShortEnumField

Strings
-------

::

    StrField(name, default, fmt="H", remain=0, shift=0)
    StrLenField(name, default, fld=None, length_from=None, shift=0):
    StrFixedLenField
    StrNullField
    StrStopField

Lists and lengths
-----------------

::

    FieldList(name, default, field, fld=None, shift=0, length_from=None, count_from=None)
      # A list assembled and dissected with many times the same field type
        
      # field: instance of the field that will be used to assemble and disassemble a list item
      # length_from: name of the FieldLenField holding the list length
         
    FieldLenField     #  holds the list length of a FieldList field
    LEFieldLenField
    
    LenField          # contains len(pkt.payload)
    
    PacketField       # holds packets
    PacketLenField    # used e.g. in ISAKMP_payload_Proposal
    PacketListField


Variable length fields
^^^^^^^^^^^^^^^^^^^^^^

This is about how fields that have a variable length can be handled with Scapy. These fields usually know their length from another field. Let's call them varfield and lenfield. The idea is to make each field reference the other so that when a packet is dissected, varfield can know its length from lenfield when a packet is assembled, you don't have to fill lenfield, that will deduce its value directly from varfield value.

Problems arise whe you realize that the relation between lenfield and varfield is not always straightforward. Sometimes, lenfield indicates a length in bytes, sometimes a number of objects. Sometimes the length includes the header part, so that you must substract the fixed header length to deduce the varfield length. Sometimes the length is not counted in bytes but in 16bits words. Sometimes the same lenfield is used by two different varfields. Sometimes the same varfield is referenced by two lenfields, one in bytes one in 16bits words.

 
The length field
~~~~~~~~~~~~~~~~

First, a lenfield is declared using ``FieldLenField`` (or a derivate). If its value is None when assembling a packet, its value will be deduced from the varfield that was referenced. The reference is done using either the ``length_of`` parameter or the ``count_of`` parameter. The ``count_of`` parameter has a meaning only when varfield is a field that holds a list (``PacketListField`` or ``FieldListField``). The value will be the name of the varfield, as a string. According to which parameter is used the ``i2len()`` or ``i2count()`` method will be called on the varfield value. The returned value will the be adjusted by the function provided in the adjust parameter. adjust will be applied on 2 arguments: the packet instance and the value returned by ``i2len()`` or ``i2count()``. By default, adjust does nothing::

    adjust=lambda pkt,x: x

For instance, if ``the_varfield`` is a list

::

    FieldLenField("the_lenfield", None, count_of="the_varfield")

or if the length is in 16bits words::

    FieldLenField("the_lenfield", None, length_of="the_varfield", adjust=lambda pkt,x:(x+1)/2)

The variable length field
~~~~~~~~~~~~~~~~~~~~~~~~~

A varfield can be: ``StrLenField``, ``PacketLenField``, ``PacketListField``, ``FieldListField``, ...

For the two firsts, whe a packet is being dissected, their lengths are deduced from a lenfield already dissected. The link is done using the ``length_from`` parameter, which takes a function that, applied to the partly dissected packet, returns the length in bytes to take for the field. For instance::

    StrLenField("the_varfield", "the_default_value", length_from = lambda pkt: pkt.the_lenfield)

or

::

    StrLenField("the_varfield", "the_default_value", length_from = lambda pkt: pkt.the_lenfield-12)

For the ``PacketListField`` and ``FieldListField`` and their derivatives, they work as above when they need a length. If they need a number of elements, the length_from parameter must be ignored and the count_from parameter must be used instead. For instance::

    FieldListField("the_varfield", ["1.2.3.4"], IPField("", "0.0.0.0"), count_from = lambda pkt: pkt.the_lenfield)

Examples
^^^^^^^^

::

    class TestSLF(Packet):
        fields_desc=[ FieldLenField("len", None, length_of="data"),
                      StrLenField("data", "", length_from=lambda pkt:pkt.len) ]
    
    class TestPLF(Packet):
        fields_desc=[ FieldLenField("len", None, count_of="plist"),
                      PacketListField("plist", None, IP, count_from=lambda pkt:pkt.len) ]
    
    class TestFLF(Packet):
        fields_desc=[ 
           FieldLenField("the_lenfield", None, count_of="the_varfield"), 
           FieldListField("the_varfield", ["1.2.3.4"], IPField("", "0.0.0.0"), 
                           count_from = lambda pkt: pkt.the_lenfield) ]

    class TestPkt(Packet):
        fields_desc = [ ByteField("f1",65),
                        ShortField("f2",0x4244) ]
        def extract_padding(self, p):
            return "", p
    
    class TestPLF2(Packet):
        fields_desc = [ FieldLenField("len1", None, count_of="plist",fmt="H", adjust=lambda pkt,x:x+2),
                        FieldLenField("len2", None, length_of="plist",fmt="I", adjust=lambda pkt,x:(x+1)/2),
                        PacketListField("plist", None, TestPkt, length_from=lambda x:(x.len2*2)/3*3) ]

Test the ``FieldListField`` class::
    
    >>> TestFLF("\x00\x02ABCDEFGHIJKL")
    <TestFLF  the_lenfield=2 the_varfield=['65.66.67.68', '69.70.71.72'] |<Raw  load='IJKL' |>>


Special
-------

::

    Emph     # Wrapper to emphasize field when printing, e.g. Emph(IPField("dst", "127.0.0.1")),
    
    ActionField
    
    ConditionalField(fld, cond)
            # Wrapper to make field 'fld' only appear if
            # function 'cond' evals to True, e.g. 
            # ConditionalField(XShortField("chksum",None),lambda pkt:pkt.chksumpresent==1)
            
    
    PadField(fld, align, padwith=None)  
           # Add bytes after the proxified field so that it ends at
           # the specified alignment from its beginning

TCP/IP
------

::

    IPField
    SourceIPField
    
    IPoptionsField
    TCPOptionsField
    
    MACField
    DestMACField(MACField)
    SourceMACField(MACField)
    ARPSourceMACField(MACField)
    
    ICMPTimeStampField

802.11
------

::

    Dot11AddrMACField
    Dot11Addr2MACField
    Dot11Addr3MACField
    Dot11Addr4MACField
    Dot11SCField

DNS
---

::

    DNSStrField
    DNSRRCountField
    DNSRRField
    DNSQRField
    RDataField
    RDLenField

ASN.1
-----

::

    ASN1F_element
    ASN1F_field
    ASN1F_INTEGER
    ASN1F_enum_INTEGER
    ASN1F_STRING
    ASN1F_OID
    ASN1F_SEQUENCE
    ASN1F_SEQUENCE_OF
    ASN1F_PACKET
    ASN1F_CHOICE

Other protocols
---------------

::

    NetBIOSNameField         # NetBIOS (StrFixedLenField) 
    
    ISAKMPTransformSetField  # ISAKMP (StrLenField) 
    
    TimeStampField           # NTP (BitField)


