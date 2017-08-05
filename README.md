# LIMA CHARLIE
<img src="https://raw.github.com/refractionPOINT/limacharlie/master/doc/lc.png" width="200">

*Talk to us on the [LimaCharlie Slack Community](http://limacharlie.herokuapp.com/)*

*Stay up to date with new features and detection modules: [@rp_limacharlie](https://twitter.com/rp_limacharlie)*

*Need help? Contact other LC users via the Google Group: https://groups.google.com/d/forum/limacharlie*

*For more direct enquiries, contact us at limacharlie@refractionpoint.com*

### Free Hosted LC
A free cloud hosted version of LimaCharlie is now available at [limacharlie.io](https://limacharlie.io/).

This is a great way to test the basic "flight-recording" features of LC without doing a deployment on premise. With a short retention it's also a great way of having a cheap safety net EDR without costly deployment, maintenance and licensing.

## Documentation
**Most of the documentation is now found on the [LC wiki](https://github.com/refractionPOINT/limacharlie/wiki).**

[LimaCharlie Youtube channel](https://www.youtube.com/channel/UCR0GhNmc4gVcD9Uj07HS5AA) contains overview and tutorial videos.

## Overview
LIMA CHARLIE is an endpoint security platform. It is itself a collection of small projects all working together
to become the LC platform. LC gives you a cross-platform (Windows, OSX, Linux, Android and iOS) low-level 
environment allowing you to manage and push (in memory) additional modules to. The main module (at the moment) 
is the HBS sensor, which provides telemetry gathering and basic forensic capabilities.

The cloud component allows you to automate investigation and mitigation with the sensor in real-time using the simple
python Hunter framework.
 
Many of those individual features are provided through other platforms, so why LC? LC gives you a single 
messaging, cloud and analytic fabric that will integrate with anything and scale up. Sensor is extra-light
and installs nothing on the host.

Ultimately LC is meant to be a platform for the security community to experiment with, a starter kit to have the 
endpoint monitoring you want or to the platform enabling you to try new endpoint techniques without the hassle of
rebuilding the basics.)

## Who Uses LimaCharlie?
*If you are using LC and would like to appear here drop us a line.*

### Loki Labs
<p align="center">
  <img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/lokilabs.png" width="200" href="https://lokilabs.io">
</p>
Founded by former members of the US intelligence & military community, Loki Labs' security engineers previously held elite, highly-specialized roles working in support of offensive and defensive cybersecurity efforts. As a result, the technical team possess unique training, experience, capabilities, and insight of the tools and tactics used by adversaries to gain access to targets of interest.
<p align="center">
  <i>"In an endless sea of endpoint agents, LC stands head-and-shoulders above competing open-source and fee-based tools at a fraction of the operating cost. LC's APT detection, threat mitigation, and interoperability are best-in-class and this is why its our agent of choice."</i>
</p>

### Jigsaw Security
<p align="center">
  <img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/jigsaw-security.png" width="200" href="https://www.jigsawsecurityenterprise.com">
</p>

### MalwareLab.co.uk
Live Malware Analysis performed thinking Out of the (Sand)Box.
<p align="center">
  <img src="https://raw.github.com/refractionPOINT/limacharlie/develop/doc/users/the_malware_lab.png" width="200" href="https://malwarelab.co.uk">
</p>

## Core Values
LIMA CHARLIE's design and implementation is based on the following core values:
* Reduce friction for the development of detections and operations.
* Single cohesive platform across Operating Systems.
* Minimize performance impact on host.

## FAQ
### What is the difference between LC and GRR?
LC is a constant monitoring platform, whereas GRR is a forensic platform. Concretely it means that GRR is more adapted
to point-in-time analysis and data gathering, while LC is better at constantly be on the lookup for techniques, IOCs
or to gather telemetry to model for anomalies in the cloud. Because LC is designed to be constantly running all its
detection methods, a lot of emphasis is put on using very little resources, in contrast to a common GRR usage where an 
investigator knows malware is present on a host and doesn't mind having high usage utilization.

### Does it integrate with my infrastructure?
Absolutely, and if it currently doesn't, let us know and we'll make sure it does.
The main integration points are currently:
* CEF (Common Event Format) detection output
* Splunk / LogStash event output
* Yara support (on disk and in memory)
* Low and high level REST API to EVERYTHING

### Is it hard to try?
No, in fact it's probably one of the easiest to try ad-hoc. See the [Cloud-in-a-Can](https://github.com/refractionPOINT/limacharlie/wiki/Installing-Cloud-in-a-Can) installation guide.
It's trivially easy to install, but it also supports large scales by leveraging Apache Cassandra for storage and Beach for computing.

### Can I deploy my own rules?
Yup, LC has more flexibility to deploy your own detections, both in the back-end and on the sensor than most commercial products.
In addition to this, you can even automate large components of the follow-up investigations (getting files, memory dumps, file io etc).

### Is LC User Mode or Kernel Mode?
LC is in fact both. The core security module (HBS) is User Mode by default, but you can optionally load (automatically from the back-end) the Kernel Acquisition module.
When this module is loaded, many of the features supported by HBS in UserMode transparently begin to use more thorough and efficient Kernel APIs.
This means you can easily run UserMode only on those critical systems but KernelMode everywhere else.

## Screen Shots
### Command Line Interface
![CLI](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_cli.png)

### Web UI Host List
![HostList](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_hostlist.png)

### Web UI Host View
![HostView](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_hostview.png)

### Web UI Object View
![ObjectView](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_object.png)
