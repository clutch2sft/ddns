## pirogom/ddns
====

Simple DDNS server

Creates a program that accepts the following command line args: 
port - (the dns udp serving port default: 53) 
cport - (the http listening port for changes default:4343)
performcallback - (set this to 1 to use a callback for tracking purposes default:0)
callbackurl - (Full URL including protocol fqdn and endpoint )
cert - (Full path and filename to cerFile for https server default:cert.pem)
key - (Full path and filename to keyFile for https server default:key.pem)
useHTTPS - (set to 1 if you want to use https you must have set cert and key for this to work default:0)


You must define two envars for API key functionallity:

export UPDATEAPIKEY="your_update_api_key"
export DELETEAPIKEY="your_delete_api_key"
export CALLBACKAPIKEY="your_callback_api_key"

-OR-

sudo nano /etc/environment
UPDATEAPIKEY="your_update_api_key"
DELETEAPIKEY="your_delete_api_key"
CALLBACKAPIKEY="your_callback_api_key"

Save the file and exit.  Your choice how you handle these critical keys.