# PortPush
PortPush is a small Bash utility used for pivoting into internal networks upon compromising a public-facing host.

There are a couple of pre-requisites for this tool to work in its current state:
> Must have a means of getting the script onto the compromised host (i.e, this isn't a "remote" utility).
> Must have root privileges on the compromised host you will be pivoting from.
> Must be an IPv4 environment. Currently, IPv6 addressing or hostnames will not work.
> IPtables must be utilized on the compromised host. 
> Firewall rules are not dealt with within the script; you are responsible for poking holes through the firewall to allow this utility to function.

This utility is still very much in its early stages, but as it currently stands I have been able to reliably use it successfully in test environments and CTFs, so I decided it's in a good enough state to make public.

Here is a video demo of its basic utility: https://www.youtube.com/watch?v=Y1JhILsKsuM



