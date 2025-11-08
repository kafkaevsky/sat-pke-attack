#!/bin/zsh

### PARAMETERS

GENERATE_CLEARS_DATA=false # OPTIONS: true, false
PLAINTEXT=0 # OPTIONS: 0, 1, "random"

### OPTIONAL CIPHER DIRECTORY FILES

cipher_n__txt=false
comments_n__txt=true
# map_n__txt=true
plain_n__txt=true

###

mkdir -p "$DATA_DIRECTORY"

if $GENERATE_CLEARS_DATA;
    then ./clearall.zsh
fi

cipher_count=1
if (( $# > 0 ));
    then cipher_count="$1"
fi

###

for _ in {1..$cipher_count}; do

    if [[ $PLAINTEXT == "random" ]];
        then plaintext_n="$(shuf -i 0-1 -n 1)"
    else
        plaintext_n=$PLAINTEXT
    fi


    ### Finding smallest n so that data/cipher_n is NOT used
    n=0
    file="cipher_$n"
    cipher_n_directory="$DATA_DIRECTORY/${file}_dir"

    while [ -e "$cipher_n_directory" ]; do
        n=$(( n + 1 ))
        file="cipher_$n"
        cipher_n_directory="$DATA_DIRECTORY/${file}_dir"
    done
    mkdir $cipher_n_directory

    ### Running scripts

    if [[ $plain_n__txt ]];
        then echo "$plaintext_n" > "$cipher_n_directory/plain_$n.txt"
    fi
    
    if [[ $comments_n__txt ]]; then
        comments_n__txt_path="$cipher_n_directory/comments_$n.txt"
    else
        comments_n__txt_path="/dev/null"
    fi

    creation_time=("$( { time python3 -m src.encrypt.encrypt -y "$plaintext_n" -c "$n" -d "$(( cipher_n__txt == 1 ))" >$comments_n__txt_path ; } 2>&1 )")
    # creation_time=("$( { time python3 -m src.encrypt.encrypt -y "$plaintext_n" -c "$n" ; } )")
    echo "cipher $n created in $creation_time"


    ### Keeping track of run time
    ns_used+=($n)
    (( total_creation_time += $((${creation_time%?})) ))

    if [[ $cipher_n__txt ]]; then
        h5dump --width=1 "$cipher_n_directory/cipher_${n}.hdf5" > "$cipher_n_directory/cipher_${n}.txt"
    fi

done


### Printing run time
if [[ $cipher_count > 1 ]]; then
    FORMATTED_TIME=$(printf "%.2f" "$total_creation_time")
    echo "$cipher_count ciphers (${(j:, :)ns_used}) created in ${FORMATTED_TIME}s"
fi