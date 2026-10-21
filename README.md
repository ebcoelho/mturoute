# MTUROUTE - Debug the MTU values between you and a host

This is a fork of MTUROUTE from Eli Fulkerson [elifulkerson.com](https://elifulkerson.com/projects/mturoute.php)

mturoute is a small command line application that uses ICMP pings of various sizes in order to determine the MTU values on the path between itself and the target system. It also includes a "traceroute" like mode where it will attempt to determine the lowest MTU between the local host and each hop in the communication.

Mturoute sends a non-fragmentable icmp probe to the target IP address with a given payload size. Since the do-not-fragment bit is set, any network equipment that has an MTU setting which is smaller than the packet size will drop the packet. 

Based on the ICMP response, or the lack of a response, mturoute adjusts the payload size of its next probe. Subsequent probes are sent with a packet size midway between the highest value for which a response was received and the lowest value for which a response was not received. (For the initial conditions, the low value is 0 and the high value is whatever you set with -m, defaulting to 10000 bytes).

This process is repeated, narrowing the search space by ~50% with each cycle, terminating once the highest possible probe size has been converged upon. It then adds the 28 bytes of ICMP protocol overhead before reporting results.

## macOS

A native macOS port (Apple Silicon and Intel) lives in [`macos/`](macos/). It needs no sudo.

```
cd macos
make
./mturoute -t 1.1.1.1
```

See [macos/README.md](macos/README.md) for details.

## Windows build

```
msbuild /t:rebuild mturoute.sln
```

## Alternative

```
docker run -it alpine
  / # apk add --no-cache iputils
  / # tracepath -n -p 80 google.com
```

# History/License:

Mturoute was originally based on the ping source code available [here](http://fgouget.free.fr/bing/index-en.shtml). The license quoted there is very liberal: """All the applications are free (BSD, GNU, or even no license) and come with the source. Don't hesitate to modify them, tweak them, enhance them. I will appreciate it if you send me your suggestions, source modifications, .. """ My modifications are free under the same arrangement as the original. Like the original author, I'd love to hear any feedback.

* In October 2007, I received modifications from Ivan Pepelnjak, which I have collectively referred to on this page as v2. These modifications were the first significant update since the original release in 2005. Ivan's posts on mturoute and his modifications can be found on [his blog](http://ioshints.blogspot.com/search?q=mturoute).

* Fixes, January 2008:
```
- Fixed up some buffer size related bugs, hopefully squashing any mysterious crashes that people may
  have been having.  In particular, if large packet sizes crashed for you before (in theory) they
  should be working now.
- added a "-v" option to output version information so I don't get confused.  Since I had previously
  dubbed Ivan's version "v2", I am unceremoniously dubbing this version "v2.1".  Incremental fixes
  will be v2.2, v2.3 etc.  Huge changes, if ever, might make a v3.
- Speed fixes for dealing with unresponsive hosts.  Rather than ticking down from the base test
  value all the way to the minimum MTU, mturoute will now throw out a minimum sized packet before
  it begins.  If this minimum packet times out, we skip all the larger packets.  Under the default
  settings this should result in an approx 3 second wait for non-responsive hosts.
- Fixed some embarrassing spelling errors and cleaned up a bit of output.  Non-responsive hosts will
  no longer report things like "------------------ host: blah max: 120 bytes", rather a message about
  them being non-responsive will be issued.
```

* Update, June 2010
```
- some runtime optimizations (tries 1500 as an mtu before going whole hog and scanning the entire possible range)
- some bug fixes
```

* Update, Nov 2010
```
- Clearer output when a connection fails with an ICMP too-big response as compared to a mysterious failure
  where no ICMP response was recieved at all.
- Made debug mode clearer when using the speed optimizations.  A bit.
```

* Update, April 2011
```
- New "-x" option automatically redacts ip address and host information in the output, replacing them
  with "a.a.a.a", "b.b.b.b" etc.
- Added "-h" and "-?" that show usage information.  Running the exe with no arguments will show usage
  information as well.
- When the mtu for the previous hop is known, we start at that mtu when checking the next hop.
- No longer double checking the successful MTU.  (1500 good... 1501 bad.... 1500 good!). 
  We now remember that we were right on the money with n-1.
- Drastically increased the amount of information in debug "-d" mode.  Need to clean it up.
- If the user hasn't specified agruments for -w and -r, and we get three timeouts in a row "...", 
  mturoute now assumes that ICMP responses will not be coming and adjusts its default -w and -r
  downward.  This should speed things up for people who don't get those responses and don't provide
  their own -w and -r settings.  If either option is specified or optimization is disabled, mturoute
  will not dynamically adjust its behavior.
```
  
* Bug fix, August 2011
```
 - Fixed an off by one error in certain cases
```

* I welcome future modifications - so long as they are of a useful nature and within the spirit with which the software was offered originally.
