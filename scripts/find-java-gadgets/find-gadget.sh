for word in $(cat gadgets.txt); 
do 
	filename=$(echo $word.jar | sed 's/:/-/';)
	find $1 -name $filename
done

