#!/bin/bash

for file in jsbn/*.js; do
	dst="js/$file"
	cp "$file" "$dst.tmp"
	
	pkg=$(echo $file|sed -E -e "s/jsbn\/(.*)\.js/jsbn.\1/")
	start="dojo.provide(\"$pkg\")"
	
	echo "$start" > "$dst"
	echo >> "$dst"
	cat "$dst.tmp" >> "$dst"
	
	rm "$dst.tmp"
	
done

