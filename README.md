check_gtp_v2
============

Checks if a specified device on the gprs tunnel protocol is accessible.


### Requirements

* Perl libraries; `Net::RawIP`, `NetPacket::IP`, `NetPacket::TCP`, `Net::DNS`, `IO::Socket`, `IO::Handle`

### Usage

    check_gtp_v2.pl -h

Options:

    -H <string>               Hostname (optional / default: via apn)
    -I <string>               Interfacename 
    -p <integer>              UDP Port (optional / default: 2123)
    -P <integer>              TCP Port of the multiplex process (optional /default: 2123)
    
    -a <string>               APN
    -m <string>               MISDN
    -i <string>               IMSI
    -g <string>               GSN-Addresses comma seperated 
                              (optional / default InterfaceIpAddress)
                         
    -U <string>               Peer-ID (default: "")
    -S <string>               Password (default: "")

    -x <string>               additional hexcode to transmit (optional)
    -t <integer>,...          comma seperated list of seconds for each step before plugin will stop

    -s <integer>              seconds to sleep between CPCR and DPCQ (default: 1)
    
    -n <string>               comma seperated list of nameservers to query (optional) 

    -d <string>               download source 'hostname|ip|port|path'
    --dl-timeout <integer>    sets the download timeout in seconds (default: 10)
    --dl-not-found-warning    enable check result 'WARNING' if download results in '404 Not Found' and plugin result is not worse
    --dump-to-file <path>     write dump of downloaded data to file in <path> (string)
    --dump-to-screen          display dump of downloaded data on screen
    --dump-check              enable checking of content length
    --dump-warning            enable check result 'WARNING' if check of content length fails and plugin result is not worse
    --dump-length             enable display of content length in plugin output
    --dump-rate               enable display of download rate on plugin output
    --dump-rate-real          enable display of real download rate on plugin output

    -h, --help                display this help and exit
    -V, --version             output version information and exit
    
Example:

    $progname -I eth0 -a "blackberry.net" -m "+123456" -i "234103160051026"


