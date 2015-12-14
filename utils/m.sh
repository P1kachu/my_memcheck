#!/bin/bash

func()
{
    cp -f .forbidden src
    cd src
    /home/Stan/Dropbox/OTHERS/useful-stuff/moulinette.py main.cc ||
        ~/Downloads/useful_stuff/moulinette.py main.cc vv

    for D in `find . -mindepth 1 -maxdepth 1 -type d`
    do
        D=$(basename $D)
        cp -f .forbidden $D
        cd $D

        for file in *.cc; do
            /home/Stan/Dropbox/OTHERS/useful-stuff/moulinette.py $file ||
                ~/Downloads/useful_stuff/moulinette.py $file vv
        done

        for file in *.hh; do
            /home/Stan/Dropbox/OTHERS/useful-stuff/moulinette.py $file ||
                ~/Downloads/useful_stuff/moulinette.py $file vv
        done

        for file in *.hxx; do
            /home/Stan/Dropbox/OTHERS/useful-stuff/moulinette.py $file ||
                ~/Downloads/useful_stuff/moulinette.py $file vv
        done

        cd ..
    done
}

func $1 $2 2> /dev/null
