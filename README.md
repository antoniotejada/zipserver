# zipserver

Efficient multithreaded HTTP server of static websites stored in zip archives.

## Features
- Serve static files stored in one or more zip archives
- Compressed and uncompressed files inside a zip archive are efficiently served directly from the zip archive without having to copy/uncompress
- Multiple worker threads from a pool
- Open file handle caching (opening and closing files is 2x-3x more costly than reading them).
- Serve default index file or browseable directory lists if there's no index file
- Specify folder to use as root for a given zip archive
- Map zip archives into arbitrary server directories

## Running

```
zipserver.py --help
usage: zipserver.py [-h] [-a SERVER_ADDRESS] [-d DEBUGLEVEL] [-i INDEX_FILE]
                    [-l] [-r ZIP_ROOTDIRS] [-s ZIP_SERVEDIRS] [-t NUM_THREADS]
                    filepaths

Launch an HTTP server to serve the contents of a zip file

positional arguments:
  filepaths             comma-separated list of filepaths to the zips to serve

optional arguments:
  -h, --help            show this help message and exit
  -a SERVER_ADDRESS, --address SERVER_ADDRESS
                        server address in [host][:port] format.
  -d DEBUGLEVEL, --debuglevel DEBUGLEVEL
                        debuglevel to use (DEBUG=10, CRITICAL=50)
  -i INDEX_FILE, --index-file INDEX_FILE
                        default index file
  -l, --list-dirs       list directories when there's no index file
  -r ZIP_ROOTDIRS, --root-dirs ZIP_ROOTDIRS
                        comma-separated directories inside the zip file for
                        the server's root (use forward slashes for subdirs).
  -s ZIP_SERVEDIRS, --serve-dirs ZIP_SERVEDIRS
                        comma-separated server directories where to hook this
                        zip file (use forward slashes for subdirs).
  -t NUM_THREADS, --num-threads NUM_THREADS
                        use n threads to serve requests, 0 to service the
                        request in the same thread
```

```
zipserver.py zip1.zip,zip2.zip -s /zip1,/zip2 -i index.html -l 
```