import sys

sys.path.append("..")
import AcraNetwork.Chapter10.Chapter10 as ch10

in_file = "test.tmats"
out_file = "full.tmats"

fin = open(in_file, mode="rb")
_raw_tmats = fin.read()
fin.close()

fout = open(out_file, mode="wb")
mych10 = ch10.Chapter10()
mych10.datatype = 0x1
mych10.sequence = 0
mych10.channelID = 0
mych10.sequence = 0
mych10.payload = _raw_tmats

fout.write(mych10.pack())
fout.close()
