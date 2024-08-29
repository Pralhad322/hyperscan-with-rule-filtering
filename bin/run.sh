cd ..
make
cd ./bin    
python string_gen.py

# DIR='/home/pralhad/hyperscan/hyperscan/bin/pcap/'
# for file in "$DIR"/*
# do
#     if [ -f "$file" ]; then
#         echo "Processing file: $file"
        
#         ./pcapscan literals.txt $file
#         python rule_filter.py
#     fi
# done
./pcapscan literals.txt eternalblue.pcap
python rule_filter.py