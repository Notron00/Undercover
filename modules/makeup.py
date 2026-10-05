from colored import Fore, Back , Style
from pystyle import Colorate, Colors
from art import text2art
import os


def wipe(): # for clean outputs (2 methods lol :>)
    os.system("cls" if os.name == "nt" else "clear")

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


