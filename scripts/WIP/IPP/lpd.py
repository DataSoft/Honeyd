#!/usr/bin/python

from socket import *

if __name__ == '__main__':
  address = ('10.10.1.2', 515)
  con_soc = socket(AF_INET, SOCK_STREAM)
  con_soc.bind(address)
  con_soc.listen(1)
  
  job_codes = {'0x01':'print-waiting',
               '0x02':'recv-job',
               '0x03':'send-queue-short',
               '0x04':'send-queue-long',
               '0x05':'remove-job'}
   
  recv_job_sub = {'0x01':'abort',
                  '0x02':'recv-control-file',
                  '0x03':'recv-data-file'}
  
  cntl_file_codes = {'0x43':'class',
                     '0x48':'host',
                     '0x49':'indent',
                     '0x4A':'job-name',
                     '0x4C':'user',
                     '0x4D':'mail',
                     '0x4E':'source-name',
                     '0x50':'id',
                     '0x53':'symlink-data',
                     '0x54':'title-pr',
                     '0x55':'unlink-file',
                     '0x57':'width-out',
                     '0x31':'troff-R-font',
                     '0x32':'troff-I-font',
                     '0x33':'troff-B-font',
                     '0x34':'troff-S-font',
                     '0x63':'plot-cif',
                     '0x64':'print-dvi',
                     '0x66':'print-formatted',
                     '0x67':'plot-bu',
                     '0x6B':'kerberos-reserved',
                     '0x6C':'print-leave-control',
                     '0x6E':'print-ditroff',
                     '0x6F':'print-postscript',
                     '0x70':'print-pr',
                     '0x72':'print-fortran',
                     '0x74':'print-troff-out',
                     '0x76':'print-raster',
                     '0x7A':'palladium-reserved'}
  
  