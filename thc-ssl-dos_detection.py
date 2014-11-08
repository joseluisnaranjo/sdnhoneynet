from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

mac1 = EthAddr('00:00:00:00:00:01')
mac2 = EthAddr('00:00:00:00:00:02')
mac3 = EthAddr('00:00:00:00:00:03')
macB = EthAddr('FF:FF:FF:FF:FF:FF')
ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
p = IPAddr('10.0.0.11')

modify = (if_(match(srcip=ip1),modify(srcip=p)) >> 
          if_(match(dstip=p),modify(dstip=ip1))    )
              
l2route = (((match(dstmac=mac1) | match(dstmac=macB)) >> fwd(1)) +
           ((match(dstmac=mac2) | match(dstmac=macB)) >> fwd(2)) +
           ((match(dstmac=mac3) | match(dstmac=macB)) >> fwd(3)) )

l3route = ((match(dstip=ip1) >> fwd(1)) +
           (match(dstip=ip2) >> fwd(2)) +
           (match(dstip=ip3) >> fwd(3)) )

policy = modify >> l2route

def main():
    return policy
