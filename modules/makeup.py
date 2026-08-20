from colored import Fore, Back , Style
from pystyle import Colorate, Colors
from art import text2art
import subprocess


def wipe(): # for clean outputs (2 methods lol :>)
    try:
        subprocess.run["clear"]
    except:
        subprocess.run["cls"]

TextColor = {
    "cyan" : Fore.light_cyan,
    "red" : Fore.red_3b,
}


def rainbowieeee_text(text):
    rainbow_text = Colorate.Horizontal(
        Colors.rainbow,
        text
    )
    return rainbow_text

def dancinnn():
    print(
        rainbowieeee_text(
            text2art(
                "UNDERCOVER",
                "dancingfont"
            )
        ) 
    )


