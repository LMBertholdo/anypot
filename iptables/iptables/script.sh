# $1 interface
# $2 output file
echo $1 $2
getDate=$(date)
cat iptables-rules.new | sed 's/ens3/'"$1"'/g' | sed 's/Mon\ Jan\ 18\ 20:52:13\ 2021/'"$getDate"'/' >> $2
