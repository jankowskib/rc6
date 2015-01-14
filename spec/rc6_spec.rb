require 'spec_helper'

describe RC6 do
  describe '#new' do
    it 'generates correct context' do
      rc6 = RC6.new("\0"*31 << "i")
      expect(rc6.key).to eq([3028870244,3572793723,3718327545,2726201800,
        1247684175,706195997,2532830521,2555503768,1804502253,2040750103,
        534494623,1010195888,2475051698,2466917687,252861082,2876697921,
        1110747983,3412282497,667888956,2113937431,3632818329,2833139191,
        1317379001,260718507,1024561575,1673043788,4153311956,4195457914,
        2971504219,3768094437,3017059175,386042906,1264709844,997561140,
        84212114,704386172,233373835,2030293242,187823311,1758555660,
        3987267664,2025083350,2035471614,3977062027])
    end

  end

  describe '#encrypt!' do
    rc6 = RC6.new("\0"*31 << "i")

    it 'encrypts and decrypts a random string of block length' do
      10.times do
        sample = (0...16).map{65.+(rand(25)).chr}.join
        decoded_hash = sample.hash
        rc6.encrypt!(sample)
        expect(sample.hash).not_to eq decoded_hash

        rc6.decrypt!(sample)
        expect(sample.hash).to eq decoded_hash
      end
    end
    it 'encrypts and decrypts a random string of random length' do
      10.times do |n|
        rand_size = rand(128)
        rand_size+= 16 - (rand_size % 16) # align size to block size
        sample = (0...rand_size).map{65.+(rand(25)).chr}.join
        decoded_hash = sample.hash
        rc6.encrypt!(sample)
        expect(sample.hash).not_to eq decoded_hash

        rc6.decrypt!(sample)
        expect(sample.hash).to eq decoded_hash
      end
    end
  end

  describe '#encrypt' do
    rc6 = RC6.new("\0"*31 << "i")
    it 'encrypts and decrypts a random string of block length' do
      10.times do
        sample = (0...16).map{65.+(rand(25)).chr}.join
        coded = rc6.encrypt(sample)
        expect(coded.hash).not_to eq sample.hash

        decoded = rc6.decrypt(coded)
        expect(sample.hash).to eq decoded.hash
      end
    end
    it 'encrypts and decrypts a random string of random length' do
      10.times do |n|
        rand_size = rand(128)
        rand_size+= 16 - (rand_size % 16) # align size to block size
        sample = (0...rand_size).map{65.+(rand(25)).chr}.join
        coded = rc6.encrypt(sample)
        expect(coded.hash).not_to eq sample.hash

        decoded = rc6.decrypt(coded)
        expect(sample.hash).to eq decoded.hash
      end
    end
  end

  describe '#decrypt!' do
    rc6 = RC6.new("\0"*31 << "i")

    it 'decrypts image header using block' do
      hdr_en =  "\x2A\x99\xA2\x80\x46\xD0\x63\x98\x24\xA2\x62\x04\x93\x1E\x03" <<
                "\x95\x6D\x62\xC1\x0B\xFD\x68\x41\xEE\xC4\xA3\x55\xAD\xCF\x96" <<
                "\x8B\xF5\x14\x4A\xD3\x68\x69\xC3\x4D\xA3\xA2\x9B\x3C\xAE\x35" <<
                "\x59\x90\x1B\x3C\xEF\x39\x50\x7E\x3E\x1E\x87\xB2\x6B\x17\xF1" <<
                "\x01\x2C\xCF\xB0\xBD\xB3\xAF\x19\x7D\x3C\x55\x5B\x63\x62\x5D" <<
                "\x20\x43\x7A\x37\x2C\x14\x77\xDF\xB9\x8C\xAC\xCE\x2F\xBA\x11" <<
                "\x98\xAE\x59\x40\x53\xBB"
      hdr_de =  "\x49\x4d\x41\x47\x45\x57\x54\x59\x00\x01\x00\x00\x50\x00\x00" <<
                "\x00\x00\x00\xd0\x04\x34\x02\x10\x00\x00\xe8\xa5\x17\x00\x04" <<
                "\x00\x00\x34\x12\x00\x00\x43\x87\x00\x00\x00\x01\x00\x00\x00" <<
                "\x01\x00\x00\x01\x00\x00\x00\x00\x04\x00\x00\x29\x00\x00\x00" <<
                "\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" <<
                "\x00\x00\x00\x00\x00\x69\x6d\x67\x52\x65\x50\x61\x63\x6b\x65" <<
                "\x72\x20\x20\x20\x20\x20"
      test_de = String.new
      rc6.decrypt!(hdr_en) do |str|
        test_de << str
      end
      expect(test_de.b).to eq hdr_de.b
    end
  end

  describe '#decrypt' do
    rc6 = RC6.new("\0"*31 << "i")

    it 'decrypts image header using block' do
      hdr_en =  "\x2A\x99\xA2\x80\x46\xD0\x63\x98\x24\xA2\x62\x04\x93\x1E\x03" <<
      "\x95\x6D\x62\xC1\x0B\xFD\x68\x41\xEE\xC4\xA3\x55\xAD\xCF\x96" <<
      "\x8B\xF5\x14\x4A\xD3\x68\x69\xC3\x4D\xA3\xA2\x9B\x3C\xAE\x35" <<
      "\x59\x90\x1B\x3C\xEF\x39\x50\x7E\x3E\x1E\x87\xB2\x6B\x17\xF1" <<
      "\x01\x2C\xCF\xB0\xBD\xB3\xAF\x19\x7D\x3C\x55\x5B\x63\x62\x5D" <<
      "\x20\x43\x7A\x37\x2C\x14\x77\xDF\xB9\x8C\xAC\xCE\x2F\xBA\x11" <<
      "\x98\xAE\x59\x40\x53\xBB"
      hdr_de =  "\x49\x4d\x41\x47\x45\x57\x54\x59\x00\x01\x00\x00\x50\x00\x00" <<
      "\x00\x00\x00\xd0\x04\x34\x02\x10\x00\x00\xe8\xa5\x17\x00\x04" <<
      "\x00\x00\x34\x12\x00\x00\x43\x87\x00\x00\x00\x01\x00\x00\x00" <<
      "\x01\x00\x00\x01\x00\x00\x00\x00\x04\x00\x00\x29\x00\x00\x00" <<
      "\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" <<
      "\x00\x00\x00\x00\x00\x69\x6d\x67\x52\x65\x50\x61\x63\x6b\x65" <<
      "\x72\x20\x20\x20\x20\x20"
      test_de = String.new
      rc6.decrypt(hdr_en) do |str|
        test_de << str
      end
      expect(test_de.b.hash).to eq hdr_de.b.hash
      expect(hdr_en.b.hash).not_to eq hdr_de.b.hash
    end
  end
end
