# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Color themes for the interactive console.
"""

##################
#  Color themes  #
##################

import sys

from scapy.compat import (
    Any,
    Callable,
    Optional,
    Union,
)


class ColorTable:
    colors = {  # Format: (ansi, pygments)
        # foreground
        "black": ("\033[30m", "#ansiblack"),
        "red": ("\033[31m", "#ansired"),
        "green": ("\033[32m", "#ansigreen"),
        "yellow": ("\033[33m", "#ansiyellow"),
        "blue": ("\033[34m", "#ansiblue"),
        "purple": ("\033[35m", "#ansipurple"),
        "cyan": ("\033[36m", "#ansicyan"),
        "grey": ("\033[37m", "#ansiwhite"),
        "reset": ("\033[39m", "noinherit"),
        # background
        "bg_black": ("\033[40m", "bg:#ansiblack"),
        "bg_red": ("\033[41m", "bg:#ansired"),
        "bg_green": ("\033[42m", "bg:#ansigreen"),
        "bg_yellow": ("\033[43m", "bg:#ansiyellow"),
        "bg_blue": ("\033[44m", "bg:#ansiblue"),
        "bg_purple": ("\033[45m", "bg:#ansipurple"),
        "bg_cyan": ("\033[46m", "bg:#ansicyan"),
        "bg_grey": ("\033[47m", "bg:#ansiwhite"),
        "bg_reset": ("\033[49m", "noinherit"),
        # specials
        "normal": ("\033[0m", "noinherit"),  # color & brightness
        "bold": ("\033[1m", "bold"),
        "uline": ("\033[4m", "underline"),
        "blink": ("\033[5m", ""),
        "invert": ("\033[7m", ""),
    }
    inv_map = {v[0]: v[1] for k, v in colors.items()}

    def __repr__(self):
        return "<ColorTable>"

    def __getattr__(self, attr):
        return self.colors.get(attr, [""])[0]

    def ansi_to_pygments(self, x):  # Transform ansi encoded text to Pygments text  # noqa: E501
        # type: (str) -> str
        for k, v in self.inv_map.items():
            x = x.replace(k, " " + v)
        return x.strip()


Color = ColorTable()


def create_styler(fmt=None, before="", after="", fmt2="%s"):
    # type: (Optional[Any], str, str, str) -> Callable
    def do_style(val, fmt=fmt, before=before, after=after, fmt2=fmt2):
        # type: (Union[int, str], Optional[Any], str, str, str) -> str
        if fmt is None:
            if not isinstance(val, str):
                val = str(val)
        else:
            val = fmt % val
        return fmt2 % (before + val + after)
    return do_style


class ColorTheme:
    def __repr__(self):
        # type: () -> str
        return "<%s>" % self.__class__.__name__

    def __reduce__(self):
        return (self.__class__, (), ())

    def __getattr__(self, attr):
        # type: (str) -> Callable
        if attr in ["__getstate__", "__setstate__", "__getinitargs__",
                    "__reduce_ex__"]:
            raise AttributeError()
        return create_styler()

    def format(self, string, fmt):
        for style in fmt.split("+"):
            string = getattr(self, style)(string)
        return string


class NoTheme(ColorTheme):
    pass


class AnsiColorTheme(ColorTheme):
    def __getattr__(self, attr):
        # type: (str) -> Callable
        if attr.startswith("__"):
            raise AttributeError(attr)
        s = "style_%s" % attr
        if s in self.__class__.__dict__:
            before = getattr(self, s)
            after = self.style_normal
        elif not isinstance(self, BlackAndWhite) and attr in Color.colors:
            before = Color.colors[attr][0]
            after = Color.colors["normal"][0]
        else:
            before = after = ""

        return create_styler(before=before, after=after)

    style_normal = ""
    style_prompt = ""
    style_punct = ""
    style_id = ""
    style_not_printable = ""
    style_layer_name = ""
    style_field_name = ""
    style_field_value = ""
    style_emph_field_name = ""
    style_emph_field_value = ""
    style_packetlist_name = ""
    style_packetlist_proto = ""
    style_packetlist_value = ""
    style_fail = ""
    style_success = ""
    style_odd = ""
    style_even = ""
    style_opening = ""
    style_active = ""
    style_closed = ""
    style_left = ""
    style_right = ""
    style_logo = ""


class BlackAndWhite(AnsiColorTheme, NoTheme):
    pass


class DefaultTheme(AnsiColorTheme):
    style_normal = Color.normal
    style_prompt = Color.blue + Color.bold
    style_punct = Color.normal
    style_id = Color.blue + Color.bold
    style_not_printable = Color.grey
    style_layer_name = Color.red + Color.bold
    style_field_name = Color.blue
    style_field_value = Color.purple
    style_emph_field_name = Color.blue + Color.uline + Color.bold
    style_emph_field_value = Color.purple + Color.uline + Color.bold
    style_packetlist_name = Color.red + Color.bold
    style_packetlist_proto = Color.blue
    style_packetlist_value = Color.purple
    style_fail = Color.red + Color.bold
    style_success = Color.blue + Color.bold
    style_even = Color.black + Color.bold
    style_odd = Color.black
    style_opening = Color.yellow
    style_active = Color.black
    style_closed = Color.grey
    style_left = Color.blue + Color.invert
    style_right = Color.red + Color.invert
    style_logo = Color.green + Color.bold


class BrightTheme(AnsiColorTheme):
    style_normal = Color.normal
    style_punct = Color.normal
    style_id = Color.yellow + Color.bold
    style_layer_name = Color.red + Color.bold
    style_field_name = Color.yellow + Color.bold
    style_field_value = Color.purple + Color.bold
    style_emph_field_name = Color.yellow + Color.bold
    style_emph_field_value = Color.green + Color.bold
    style_packetlist_name = Color.red + Color.bold
    style_packetlist_proto = Color.yellow + Color.bold
    style_packetlist_value = Color.purple + Color.bold
    style_fail = Color.red + Color.bold
    style_success = Color.blue + Color.bold
    style_even = Color.black + Color.bold
    style_odd = Color.black
    style_left = Color.cyan + Color.invert
    style_right = Color.purple + Color.invert
    style_logo = Color.green + Color.bold


class RastaTheme(AnsiColorTheme):
    style_normal = Color.normal + Color.green + Color.bold
    style_prompt = Color.yellow + Color.bold
    style_punct = Color.red
    style_id = Color.green + Color.bold
    style_not_printable = Color.green
    style_layer_name = Color.red + Color.bold
    style_field_name = Color.yellow + Color.bold
    style_field_value = Color.green + Color.bold
    style_emph_field_name = Color.green
    style_emph_field_value = Color.green
    style_packetlist_name = Color.red + Color.bold
    style_packetlist_proto = Color.yellow + Color.bold
    style_packetlist_value = Color.green + Color.bold
    style_fail = Color.red
    style_success = Color.red + Color.bold
    style_even = Color.yellow
    style_odd = Color.green
    style_left = Color.yellow + Color.invert
    style_right = Color.red + Color.invert
    style_logo = Color.green + Color.bold


class ColorOnBlackTheme(AnsiColorTheme):
    """Color theme for black backgrounds"""
    style_normal = Color.normal
    style_prompt = Color.green + Color.bold
    style_punct = Color.normal
    style_id = Color.green
    style_not_printable = Color.black + Color.bold
    style_layer_name = Color.yellow + Color.bold
    style_field_name = Color.cyan
    style_field_value = Color.purple + Color.bold
    style_emph_field_name = Color.cyan + Color.bold
    style_emph_field_value = Color.red + Color.bold
    style_packetlist_name = Color.black + Color.bold
    style_packetlist_proto = Color.yellow + Color.bold
    style_packetlist_value = Color.purple + Color.bold
    style_fail = Color.red + Color.bold
    style_success = Color.green
    style_even = Color.black + Color.bold
    style_odd = Color.grey
    style_opening = Color.yellow
    style_active = Color.grey + Color.bold
    style_closed = Color.black + Color.bold
    style_left = Color.cyan + Color.bold
    style_right = Color.red + Color.bold
    style_logo = Color.green + Color.bold


class FormatTheme(ColorTheme):
    def __getattr__(self, attr):
        # type: (str) -> Callable
        if attr.startswith("__"):
            raise AttributeError(attr)
        colfmt = self.__class__.__dict__.get("style_%s" % attr, "%s")
        return create_styler(fmt2=colfmt)


class LatexTheme(FormatTheme):
    style_prompt = r"\textcolor{blue}{%s}"
    style_not_printable = r"\textcolor{gray}{%s}"
    style_layer_name = r"\textcolor{red}{\bf %s}"
    style_field_name = r"\textcolor{blue}{%s}"
    style_field_value = r"\textcolor{purple}{%s}"
    style_emph_field_name = r"\textcolor{blue}{\underline{%s}}"  # ul
    style_emph_field_value = r"\textcolor{purple}{\underline{%s}}"  # ul
    style_packetlist_name = r"\textcolor{red}{\bf %s}"
    style_packetlist_proto = r"\textcolor{blue}{%s}"
    style_packetlist_value = r"\textcolor{purple}{%s}"
    style_fail = r"\textcolor{red}{\bf %s}"
    style_success = r"\textcolor{blue}{\bf %s}"
    style_left = r"\textcolor{blue}{%s}"
    style_right = r"\textcolor{red}{%s}"
#    style_even = r"}{\bf "
#    style_odd = ""
    style_logo = r"\textcolor{green}{\bf %s}"


class LatexTheme2(FormatTheme):
    style_prompt = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_not_printable = r"@`@textcolor@[@gray@]@@[@%s@]@"
    style_layer_name = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_field_name = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_field_value = r"@`@textcolor@[@purple@]@@[@%s@]@"
    style_emph_field_name = r"@`@textcolor@[@blue@]@@[@@`@underline@[@%s@]@@]@"
    style_emph_field_value = r"@`@textcolor@[@purple@]@@[@@`@underline@[@%s@]@@]@"  # noqa: E501
    style_packetlist_name = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_packetlist_proto = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_packetlist_value = r"@`@textcolor@[@purple@]@@[@%s@]@"
    style_fail = r"@`@textcolor@[@red@]@@[@@`@bfseries@[@@]@%s@]@"
    style_success = r"@`@textcolor@[@blue@]@@[@@`@bfserices@[@@]@%s@]@"
    style_even = r"@`@textcolor@[@gray@]@@[@@`@bfseries@[@@]@%s@]@"
#    style_odd = r"@`@textcolor@[@black@]@@[@@`@bfseries@[@@]@%s@]@"
    style_left = r"@`@textcolor@[@blue@]@@[@%s@]@"
    style_right = r"@`@textcolor@[@red@]@@[@%s@]@"
    style_logo = r"@`@textcolor@[@green@]@@[@@`@bfseries@[@@]@%s@]@"


class HTMLTheme(FormatTheme):
    style_prompt = "<span class=prompt>%s</span>"
    style_not_printable = "<span class=not_printable>%s</span>"
    style_layer_name = "<span class=layer_name>%s</span>"
    style_field_name = "<span class=field_name>%s</span>"
    style_field_value = "<span class=field_value>%s</span>"
    style_emph_field_name = "<span class=emph_field_name>%s</span>"
    style_emph_field_value = "<span class=emph_field_value>%s</span>"
    style_packetlist_name = "<span class=packetlist_name>%s</span>"
    style_packetlist_proto = "<span class=packetlist_proto>%s</span>"
    style_packetlist_value = "<span class=packetlist_value>%s</span>"
    style_fail = "<span class=fail>%s</span>"
    style_success = "<span class=success>%s</span>"
    style_even = "<span class=even>%s</span>"
    style_odd = "<span class=odd>%s</span>"
    style_left = "<span class=left>%s</span>"
    style_right = "<span class=right>%s</span>"


class HTMLTheme2(HTMLTheme):
    style_prompt = "#[#span class=prompt#]#%s#[#/span#]#"
    style_not_printable = "#[#span class=not_printable#]#%s#[#/span#]#"
    style_layer_name = "#[#span class=layer_name#]#%s#[#/span#]#"
    style_field_name = "#[#span class=field_name#]#%s#[#/span#]#"
    style_field_value = "#[#span class=field_value#]#%s#[#/span#]#"
    style_emph_field_name = "#[#span class=emph_field_name#]#%s#[#/span#]#"
    style_emph_field_value = "#[#span class=emph_field_value#]#%s#[#/span#]#"
    style_packetlist_name = "#[#span class=packetlist_name#]#%s#[#/span#]#"
    style_packetlist_proto = "#[#span class=packetlist_proto#]#%s#[#/span#]#"
    style_packetlist_value = "#[#span class=packetlist_value#]#%s#[#/span#]#"
    style_fail = "#[#span class=fail#]#%s#[#/span#]#"
    style_success = "#[#span class=success#]#%s#[#/span#]#"
    style_even = "#[#span class=even#]#%s#[#/span#]#"
    style_odd = "#[#span class=odd#]#%s#[#/span#]#"
    style_left = "#[#span class=left#]#%s#[#/span#]#"
    style_right = "#[#span class=right#]#%s#[#/span#]#"


def apply_ipython_style(shell):
    # type: (Any) -> None
    """Updates the specified IPython console shell with
    the conf.color_theme scapy theme."""
    try:
        from IPython.terminal.prompts import Prompts, Token
    except Exception:
        from scapy.error import log_loading
        log_loading.warning(
            "IPython too old. Shell color won't be handled."
        )
        return
    from scapy.config import conf
    scapy_style = {}
    # Overwrite colors
    if isinstance(conf.color_theme, NoTheme):
        shell.colors = 'nocolor'
    elif isinstance(conf.color_theme, BrightTheme):
        # lightbg is optimized for light backgrounds
        shell.colors = 'lightbg'
    elif isinstance(conf.color_theme, ColorOnBlackTheme):
        # linux is optimised for dark backgrounds
        shell.colors = 'linux'
    else:
        # default
        shell.colors = 'neutral'
    try:
        get_ipython()
        # This function actually contains tons of hacks
        color_magic = shell.magics_manager.magics["line"]["colors"]
        color_magic(shell.colors)
    except NameError:
        pass
    # Prompt Style
    if isinstance(conf.prompt, Prompts):
        # Set custom prompt style
        shell.prompts_class = conf.prompt
    else:
        if isinstance(conf.color_theme, (FormatTheme, NoTheme)):
            # Formatable
            if isinstance(conf.color_theme, HTMLTheme):
                from scapy.compat import html_escape
                prompt = html_escape(conf.prompt)
            elif isinstance(conf.color_theme, LatexTheme):
                from scapy.utils import tex_escape
                prompt = tex_escape(conf.prompt)
            else:
                prompt = conf.prompt
            prompt = conf.color_theme.prompt(prompt)
        else:
            # Needs to be manually set
            prompt = str(conf.prompt)
            scapy_style[Token.Prompt] = Color.ansi_to_pygments(
                conf.color_theme.style_prompt
            )

        class ClassicPrompt(Prompts):
            def in_prompt_tokens(self, cli=None):
                return [(Token.Prompt, prompt), ]

            def out_prompt_tokens(self):
                return [(Token.OutPrompt, ''), ]
        # Apply classic prompt style
        shell.prompts_class = ClassicPrompt
        sys.ps1 = prompt
    # Register scapy color style
    shell.highlighting_style_overrides = scapy_style
    # Apply if Live
    try:
        get_ipython().refresh_style()
    except NameError:
        pass
