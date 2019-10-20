#!/bin/bash

if [[ $(pwd) != *"doc/syntax/vim_uts_syntax" ]]
then
	echo "Wrong current directory. Please call this script if you are inside doc/syntax/vim_uts_syntax"
	exit -1
fi

if [ ! -d "$HOME/.vim" ]; then
	echo "$HOME/.vim doesn't exist"
	exit -1
fi

if [ -f "$HOME/.vim/ftdetect/filetype.vim" ]; then
    echo "$HOME/.vim/ftdetect/filetype.vim already exists. You may not want to overwrite this file."
fi

mkdir -p -v $HOME/.vim/ftdetect
mkdir -p -v $HOME/.vim/syntax

cp -i -v ftdetect/filetype.vim $HOME/.vim/ftdetect/filetype.vim
cp -i -v ftdetect/uts.vim $HOME/.vim/ftdetect/uts.vim
cp -i -v syntax/uts.vim $HOME/.vim/syntax/uts.vim

echo "Installed"
