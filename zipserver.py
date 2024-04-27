#!/usr/bin/env python
"""
Efficient multithreaded HTTP web server from files stored in zip archives
(c) Antonio Tejada 2024

See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
See https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
"""

import argparse
import __builtin__
import cgi
import datetime
import logging
import os
import posixpath
import Queue
import SimpleHTTPServer
import SocketServer
import socket
import string
import StringIO
import struct
import sys
import threading
import urllib
import urlparse
import zipfile

# Some places use zip as variable overwriting the built-in zip(), use
# interleave() instead 
# XXX Don't overwrite it?
interleave = __builtin__.zip

def class_name(o):
    return o.__class__.__name__

class LineHandler(logging.StreamHandler):
    """
    Split lines in multiple records, fill in %(className)s
    """
    def __init__(self):
        super(LineHandler, self).__init__()

    def emit(self, record):
        # Find out class name, _getframe is supposed to be faster than inspect,
        # but less portable
        # caller_locals = inspect.stack()[6][0].f_locals
        caller_locals = sys._getframe(6).f_locals
        clsname = ""
        zelf = caller_locals.get("self", None)
        if (zelf is not None):
            clsname = class_name(zelf) + "."
            zelf = None
        caller_locals = None
        
        # Indent all lines but the first one
        indent = ""
        text = record.getMessage()
        messages = text.split('\n')
        for message in messages:
            r = record
            r.msg = "%s%s" % (indent, message)
            r.className = clsname
            r.args = None
            super(LineHandler, self).emit(r)
            indent = "    " 

def setup_logger(logger):
    """
    Setup the logger with a line break handler
    """
    logging_format = "%(asctime).23s %(levelname)s:%(filename)s(%(lineno)d):[%(thread)d] %(className)s%(funcName)s: %(message)s"

    logger_handler = LineHandler()
    logger_handler.setFormatter(logging.Formatter(logging_format))
    logger.addHandler(logger_handler) 

    return logger


class ThreadingPoolTCPServer(SocketServer.TCPServer):
    """
    Similar to ThreadingTCPServer (TreadingMixIn) but it uses a pool of threads
    instead of creating a new thread for each request

    Besides avoiding continuously creating threads, this also allows the request
    handler to have thread-local-storage data reusable across requests
    """
    def __init__(self, num_threads, *args, **kwargs):
        # Call the method directly, don't use super() since TCPServer is not a
        # new Python class type
        SocketServer.TCPServer.__init__(self, *args, **kwargs)
        # Note the size of the queue is somewhat arbitrary and unrelated to the
        # number of threads, but threads + queue size = outstanding requests
        # Looks like Microsoft Edge won't initiate more than 3 simultaneous
        # requests with 3 more sent little after for a total of 6 outstanding
        # See https://learn.microsoft.com/en-us/microsoft-edge/devtools-guide-chromium/network/issues
        # Additionally, using a queue as long as the number of threads allows
        # purging to not get stuck when one of the worker threads is stuck
        # (because of client keepalive?)
        self.work_queue = Queue.Queue(num_threads)
        self.max_queue_size = 0
        self.busy_threads = 0
        self.num_threads = num_threads

        logger.info("Starting %d threads", num_threads)
        for i in xrange(num_threads):
            t = threading.Thread(target = self.process_request_thread)
            t.start()

    def process_request_thread(self):
        while (True):
            logger.info("Waiting for work")
            work = self.work_queue.get()
            logger.info("Waited for work %s", work)
            self.busy_threads += 1
            if (work is None):
                logger.info("Exiting thread")
                break

            # Uncomment do debug number of simultaneous client requests
            #import time
            #time.sleep(5)

            request, client_address = work
            try:
                self.finish_request(request, client_address)
                self.shutdown_request(request)
  
            except:
                logger.exception("Exception")
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            self.busy_threads -= 1

    def process_request(self, request, client_address):
        qsize = self.work_queue.qsize()
        self.max_queue_size = max(qsize, self.max_queue_size)
        logger.info("Queueing work %d busy %d/%d queued %d outstanding", self.busy_threads, qsize, self.max_queue_size, self.busy_threads + qsize)
        self.work_queue.put((request, client_address))
        qsize = self.work_queue.qsize()
        self.max_queue_size = max(qsize, self.max_queue_size)
        logger.info("Queued work %d busy %d/%d queued %d outstanding", self.busy_threads, qsize, self.max_queue_size, self.busy_threads + qsize)

    def serve_forever(self, poll_interval=0.5):
        try:
            # This hangs on keyboard interrupt, requiring to "pump" the socket
            # with a request so the script exits. Another option is to offload
            # serve_forever() to a non daemon thread (thread.daemon = False),
            # which makes Python not wait for alive threads when the main thread
            # wants to exit (at the expense of corrupting whatever the pending
            # threads are doing and not doing any necessary cleanup, which may
            # not be an issue if the webserver is "readonly")
            SocketServer.TCPServer.serve_forever(self, poll_interval)
        finally:
            if (self.num_threads >= 1):
                logger.info("Purging threads")
                for i in xrange(self.num_threads):
                    self.work_queue.put(None)

class ZippedHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """
    HTTP server handler that can efficiently serve files inside zip archives
    """

    # Add some recent extensions so guess_type works (note adding these with
    # mimetypes.add_type would require adding them after mimetypes is
    # imported but before SimpleHTTPServer is imported, which is kludgy)
    SimpleHTTPServer.SimpleHTTPRequestHandler.extensions_map.update({
        ".webp" : "image/webp"
    })
    
    def do_GET(self):
        # The default implementation closes the file unconditionally, override
        f = self.send_head()
        if (f is not None):
            try:
                self.copyfile(f, self.wfile)
            finally:
                if (self.close_file):
                    f.close()
                
    def do_HEAD(self):
        # The default implementation closes the file unconditionally, override
        f = self.send_head()
        if (self.close_file):
            f.close()
            
    def log_message(self, format, *args):
        # The default implementation logs to stderr, override
        logger.info(format, *args)

    def log_error(self, format, *args):
        # The default implementation logs to stderr, override
        logger.error(format, *args)

    def copyfile(self, src, dst):
        """
        The default implementation sends the whole file in chunks (optionally
        specifying the chunk size), override and send only content_length bytes.

        Copy self.content-length bytes between two file objects. 

        Assumes send_head has been previously called in order to set
        self.content_length

        The SOURCE argument is a file object open for reading (or anything with
        a read() method) and the DESTINATION argument is a file object open for
        writing (or anything with a write() method).

        Caller is responsible of closing both files.
        """
        # When doing pass-through compressed transfers where the files to copy
        # are inside a bigger compressed file, src will be larger than
        # requested, cap all transfers to the next content-length bytes at the
        # current position

        # Don't use shutil.copyfileobj since the length parameter in that
        # function is the block size, not the size to copy
        length = self.content_length
        logger.debug("copying %r %d bytes", self.path, length)
        block_length = 16*1024
        while (length > 0):
            buf = src.read(min(block_length, length))
            assert buf != ""
            dst.write(buf)
            length -= len(buf)
        # src and dst should be closed by caller
        logger.debug("copied %r %d bytes left", self.path, length)

    
    def send_directory(self, path):
        """
        Helper to produce a directory listing (absent index.html).

        @param path posixpath without leading forwardslash, with trailing
               forwardslash, already URL decoded

        Return value is either a file object, or None (indicating an error).  In
        either case, the headers are sent, making the interface the same as for
        send_head() so it can be called from there.

        """
        logger.info("%r", path)
        
        # Collect entries first so they can be sorted when rendered to HTML
        # path is "" for the root, forward slash terminated for directories
        # This supports:
        # - Collecting files from the same directory on multiple zip files
        # - Only listing from an arbitrary zip subdirectory (zip_rootdir)
        # - hooking the zip root directory on an arbitrary server directory (servedir)
        
        entries = []
        dirs = set()
        logger.debug("Building directory list")
        for zip, zip_rootdir, zip_servedir in interleave(g_zips, g_zip_rootdirs, g_zip_servedirs):
            # XXX Rationalize all this leading/trailing slash
            if (zip_servedir[0] != "/"):
                zip_servedir = "/" + zip_servedir

            if (posixpath.dirname(zip_servedir[:-1]) == path):
                # If this path is the parent of a servedir, add an entry for
                # this zip at this servedir
                entry_rootname = zip_servedir[1:]
                name = zip_rootdir + "/"
                date = ""
                size = "-"
                try:
                    zip_info = zip.getinfo(name)
                    date = zip_info.date_time
                    date = "%d-%02d-%02d %02d:%02d:%02d" % date
                except KeyError:
                    pass
                entries.append((entry_rootname, date, size))
                continue
            
            elif (not path.startswith(zip_servedir)):
                continue

            zip_abspath = path[len(zip_servedir):]
            zip_abspath = posixpath.join(zip_rootdir, zip_abspath)
            logger.debug("zippath %r", zip_abspath)

            for info in zip.infolist():
                name = info.filename
                # Add all the entries with this parent dir
                if (name.startswith(zip_abspath)):
                    size = "-"
                    date = ""
                    entry_rootname = name[len(zip_abspath):]
                    if (entry_rootname == ""):
                        # Parent entry, ignore (note some zips may not have
                        # directory entries so will never get here, entry will
                        # be added on non top dirs after sorting below)
                        continue
                    slash_pos = entry_rootname.find("/")
                    if (slash_pos > -1):
                        # Subdirectory or file inside a subdirectory, add the
                        # subdirectory only once. Note subdirectories may or may
                        # not have a dedicated entry in the zip file so they
                        # have to be derived from files inside the subdirectory
                        entry_rootname = entry_rootname[:slash_pos+1]
                        if (entry_rootname in dirs):
                            # Already dealt-with subdirectory, ignore
                            continue
                        name = posixpath.dirname(name) + "/"
                            
                        dirs.add(entry_rootname)
                        if (slash_pos == (len(entry_rootname)-1)):
                            date = info.date_time

                    else:
                        date = info.date_time
                        size = info.file_size
                    
                    if (date != ""):
                        date = "%d-%02d-%02d %02d:%02d:%02d" % date
                    entries.append((entry_rootname, date, size))

        def cmp_entries(a, b):
            # XXX This could sort by other fields if sort order is passed in eg
            #     url fragment
            a_name = a[0].lower()
            b_name = b[0].lower()
            a_isdir = a_name.endswith("/")
            b_isdir = b_name.endswith("/")
            # Sort directories first alphabetically lowercase, then files
            # alphabetically lowercase
            if (a_isdir != b_isdir):
                if (a_isdir):
                    return -1
                else:
                    return 1
            else:
                return cmp(a_name, b_name)

        entries.sort(cmp=cmp_entries)
        # Add go to parent unless it's the top dir
        if (path != "/"):
            entries.insert(0, ("..", "-", ""))

        logger.debug("Built directory list")

        # If the path was found in the file, there should always be one "go to
        # parent entry", otherwise the path doesn't exist
        # XXX This should never happen since the caller guarantees the path is
        #     valid?
        if (len(entries) == 0):
            self.send_error(404, "File not found")
            return None

        f = StringIO.StringIO()
        displaypath = cgi.escape(path)
        # XXX Display some kind of search/filter box? should it search only in
        #     this directory or across all?
        f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write("<html>\n<head><title>Directory listing for %s</title>\n" % displaypath)
        f.write("<style>body { font-family: monospace }</style></head>\n")
        prev_slash_pos = -1
        crumbs = []
        while (True):
            slash_pos = displaypath.find("/", prev_slash_pos+1)
            if (slash_pos >= len(displaypath) - 1):
                crumbs.append(displaypath[prev_slash_pos+1:slash_pos+1])
                break
            crumbs.append("<A HREF=\"%s\">%s</A>" % (displaypath[:slash_pos+1], displaypath[prev_slash_pos+1:slash_pos+1]))
            prev_slash_pos = slash_pos
        f.write("<body>\n<h2>Directory listing for %s</h2>\n" % string.join(crumbs, " "))
        f.write("<hr>\n<table><th><tr><td>Name</td><td>Size</td><td>Date</td></tr></th>\n")
        logger.debug("Writing directory list")
        for name, date, size in entries:
            if (name == ".."):
                linkname = posixpath.dirname(path[:-1])
            else:
                linkname = posixpath.join(path, name)

            f.write('<tr><td><a href="%s">%s</a></td><td>%s</td><td>%s</td></tr>\n'
                % (urllib.quote(linkname), cgi.escape(name), size, date))

        logger.debug("Written directory list")
        f.write("</table>\n<hr>\n</body>\n</html>\n")
        # XXX Writing to a string and then to a file is inefficient, ideally
        #     send directly and without content-length, in theory it's valid for
        #     both GET and HEAD requests, but then send_directory must not send
        #     any data when it's a HEAD request
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        # cp437/ibm437 is the default zip encoding
        # XXX Some zips also support utf-8, where to check? does python handle
        #     transparently and use utf-8 by default?
        encoding = "IBM437"
        self.send_header("Content-type", "text/html; charset=%s" % encoding)
        self.content_length = length
        self.send_header("Content-Length", str(length))
        # Use the most recent zip modified time as date for the directory
        # listing
        d = datetime.datetime.utcfromtimestamp(0)
        for zip in g_zips:
            d = max(d, datetime.datetime.utcfromtimestamp(os.path.getmtime(zip.filename)))
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[d.weekday()],
                d.day, self.monthname[d.month], d.year,
                d.hour, d.minute, d.second)
        self.send_header("Last-Modified", s)

        self.end_headers()
        return f


    def send_head(self):
        # url path uses forward slashes and leading slash, zip paths use no
        # leading slash and forward slashes.
        #
        # Some zips may have individual directory entries, slash terminated but
        # some other zip files don't have those entries even if they have files
        # in those directories. Directories inside a zip have trailing forward
        # slash.
        #
        # See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
        logger.info("%r", self.path)

        self.close_file = False
            
        path = self.path

        # Ignore query and fragments
        
        # XXX This will break websites with internal links with fragment in the
        #     URL links to the fragment urls. Have a flag? remove those when
        #     searching the zip? (but will fail to resolve files with the same
        #     path but different querystring)
        path = urlparse.urlparse(path).path
    
        # Translate url and normalize multiple //, etc
        # Use posixpath explicitly instead of the native-os os.path since it
        # deals with forward slashes exclusively
        path = urllib.unquote(path)
        path = posixpath.normpath(path)
        # Double forward slash // turns into ".", remove
        if (path == "."):
            path = ""
        else:
            # Remove leading slash
            assert path[0] == "/"
            path = path[1:]
        rel_path = path

        logger.debug("normpath %r", path)
        logger.debug("searching path in zips")
        zip_info = None
        list_dir = False
        for zip, zip_rootdir, zip_servedir in interleave(g_zips, g_zip_rootdirs, g_zip_servedirs):
            if (rel_path.startswith(zip_servedir) or (rel_path == zip_servedir[:-1])):
                # Note for empty paths, join will forward slash terminate
                path = posixpath.join(zip_rootdir, rel_path[len(zip_servedir):])
            else:
                path = posixpath.join(zip_rootdir, rel_path)
            logger.info("zippath %r", path)
            try:
                # Zips entries use forward slashes, for directories, the zip
                # contains an entry with a terminating forward slash
                zip_info = zip.getinfo(path)

            except KeyError:
                try:
                    # Allow input paths for directories with no terminating
                    # slash
                    zip_info = zip.getinfo(path + "/")
                    path = path + "/"
                except KeyError:
                    # Some zips don't have individual entries for directories, 
                    # find any subdirectory 
                    for name in zip.namelist():
                        if (name.startswith(path)):
                            if (not path.endswith("/")):
                                path += "/"
                            list_dir = True
                            break
                    else:
                        continue
                    
            # Use the index file if directory
            if (path.endswith("/") and (g_index_file != "")):
                index_path = posixpath.join(path, g_index_file)
                try:
                    zip_info = zip.getinfo(index_path)
                    path = index_path
                except KeyError:
                    pass
            break

        logger.debug("searched path in zips")

        if ((zip_info is None) and not list_dir):
            self.send_error(404, "File not found")
            return None

        elif (path.endswith("/")):
            if (g_list_dirs):
                # List directory
                
                # rel_path may not be forward slash terminated if it was appended
                # above or if it's the root of a serverdir, add it
                rel_path = "/" + rel_path
                if (not rel_path.endswith("/")):
                    rel_path += "/"

                logger.debug("serving dir %r", rel_path)
                return self.send_directory(rel_path)

            else:
                self.send_error(404, "File not found")
                return None
        
        ctype = self.guess_type(path)
        logger.debug("serving file %r type %s", path, ctype)

        # Pass through compressed data if the compression format is deflate
        # and the client accepts deflate or if there's no compression
        accepted_encodings = self.headers.get("accept-encoding").split(",")
        logger.debug("accept-encoding %s", accepted_encodings)
        serve_compressed = any([encoding.strip() == "deflate" for encoding in accepted_encodings])
        serve_compressed = serve_compressed and (zip_info.compress_type == zipfile.ZIP_DEFLATED)
        if (serve_compressed or (zip_info.compress_type == zipfile.ZIP_STORED)):
            # Open and close take 4x than read, cache the open files
            # thread-safely
            # XXX Could use mmap too?
            if (getattr(g_tls, 'files', None) is None):
                g_tls.files = {}
            f = g_tls.files.get(zip.filename, None)
            # Check for f.closed so closing vs. recycling can be easily profiled
            # by setting close_file below
            if ((f is None) or f.closed):
                logger.info("Opening zip file %r", zip.filename)
                f = open(zip.filename, 'rb')
                g_tls.files[zip.filename] = f
            self.close_file = False

            logger.debug("serving passthrough type %d", zip_info.compress_type)
            logger.debug("seeking to %d for %r", zip_info.header_offset, path)
            f.seek(zip_info.header_offset, 0)
            
            # Skip the file header, see zipfile.ZipFile.open
            # and https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
            fheader = f.read(zipfile.sizeFileHeader)
            if (len(fheader) != zipfile.sizeFileHeader):
                raise zipfile.BadZipfile("Truncated file header")
            fheader = struct.unpack(zipfile.structFileHeader, fheader)
            if (fheader[zipfile._FH_SIGNATURE] != zipfile.stringFileHeader):
                raise zipfile.BadZipfile("Bad magic number for file header")

            f.read(fheader[zipfile._FH_FILENAME_LENGTH])
            if (fheader[zipfile._FH_EXTRA_FIELD_LENGTH]):
                f.read(fheader[zipfile._FH_EXTRA_FIELD_LENGTH])
                    
        else:
            logger.debug("serving uncompressing type %d", zip_info.compress_type)
            f = zip.open(path, 'r')
            self.close_file = True
        
        try:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            if (serve_compressed):
                self.send_header("Content-Encoding", "deflate")
                self.content_length = zip_info.compress_size

            else:
                self.content_length = zip_info.file_size
            self.send_header("Content-Length", self.content_length)
                
            d = datetime.datetime(*zip_info.date_time)
            # XXX zip stores DOS times which are not GMT, but this assumes GMT
            #     maybe should convert from local time instead
            s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                    self.weekdayname[d.weekday()],
                    d.day, self.monthname[d.month], d.year,
                    d.hour, d.minute, d.second)
            self.send_header("Last-Modified", s)
            self.end_headers()
            return f
        
        except:
            if (self.close_file):
                f.close()
            raise

def main():
    global g_zip_rootdirs
    global g_zip_servedirs
    global g_zips
    global g_index_file
    global g_tls
    global g_list_dirs

    g_tls = threading.local()

    parser = argparse.ArgumentParser(
        description='Launch an HTTP server to serve the contents of a zip file', 
    )

    parser.add_argument('-a', '--address', action='store', dest='server_address', help="server address in [host][:port] format.", default=':8000')
    
    parser.add_argument('-d', '--debuglevel', action='store', dest='debuglevel', help="debuglevel to use (DEBUG=10, CRITICAL=50)", default=logging.WARNING, type=int)
    # XXX Allow multiple index files/regexp/globexp?
    # XXX Have a case-insensitive flag for the index file?
    parser.add_argument('-i', '--index-file', action='store', dest='index_file', help="default index file", default="")
    parser.add_argument('-l', '--list-dirs', action='store_true', dest='list_dirs', help="list directories when there's no index file", default=False)
    parser.add_argument('-r', '--root-dirs', action='store', dest='zip_rootdirs', help="comma-separated directories inside the zip file for the server's root (use forward slashes for subdirs).", default="")
    parser.add_argument('-s', '--serve-dirs', action='store', dest='zip_servedirs', help="comma-separated server directories where to hook this zip file (use forward slashes for subdirs).", default="")
    parser.add_argument('-t', '--num-threads', action='store', dest='num_threads', help="use n threads to serve requests, 0 to service the request in the same thread", default= 6, type=int)
    parser.add_argument('filepaths', action='store', help='comma-separated list of filepaths to the zips to serve')

    args = parser.parse_args()

    server_address = args.server_address.split(":")
    if (len(server_address) > 1):
        server_address[1] = int(server_address[1])
    else:
        server_address[1] = 8000

    zip_filepaths = args.filepaths
    g_index_file = args.index_file
    g_zip_rootdirs = args.zip_rootdirs
    g_zip_servedirs = args.zip_servedirs
    num_threads = args.num_threads
    debuglevel = args.debuglevel
    g_list_dirs = args.list_dirs

    logger.setLevel(debuglevel)

    zip_filepaths = zip_filepaths.split(",")
    g_zip_rootdirs = g_zip_rootdirs.split(",")
    g_zip_servedirs = g_zip_servedirs.split(",")

    req_len = len(zip_filepaths)
    if (len(g_zip_servedirs) > req_len):
        parser.error("More servedirs %d than filepaths %d!", len(g_zip_servedirs), len(zip_filepaths))
    if (len(g_zip_rootdirs) > req_len):
        parser.error("More rootdirs %d than filepaths %d!", len(g_zip_rootdirs), len(zip_filepaths))

    # Fill with default values if there are less than filepaths
    g_zip_rootdirs.extend([""] * (req_len - len(g_zip_rootdirs)))
    g_zip_servedirs.extend(["/"] * (req_len - len(g_zip_servedirs)))

    # For the time being, 
    # - rootdirs must have forward slashes and no leading or trailing slash
    # - servedirs must have trailing slash but no leading slash
    # XXX Unify all this slash suffix/prefix around the code

    # Remove leading slash and add trailing slash to g_zip_servedirs
    g_zip_servedirs = [zip_servedir[1:] if (zip_servedir.startswith("/")) else zip_servedir for zip_servedir in g_zip_servedirs]
    g_zip_servedirs = [zip_servedir if (zip_servedir.endswith("/")) else zip_servedir + "/" for zip_servedir in g_zip_servedirs]

    # Remove leading slash from g_zip_rootdirs
    g_zip_rootdirs = [zip_rootdir[1:] if (zip_rootdir.startswith("/")) else zip_rootdir for zip_rootdir in g_zip_rootdirs]

    logger.info("Serving zips %s at %s with index %s roots %s serves %s", zip_filepaths, (socket.gethostbyname_ex(socket.gethostname()), server_address[1]), g_index_file, g_zip_rootdirs, g_zip_servedirs)

    # XXX Store also the rootdir and the serverdir so there's no need to zip()
    #     elsewhere?
    g_zips = [zipfile.ZipFile(zip_filepath, "r") for zip_filepath in zip_filepaths]

    handler_class = ZippedHTTPRequestHandler
    if (num_threads >= 1):
        # Note there will be a main thread receiving the request and num_threads
        # servicing them
        httpd = ThreadingPoolTCPServer(num_threads, tuple(server_address), handler_class)

    else:
        # Same thread receiving and servicing the request
        httpd = SocketServer.TCPServer(tuple(server_address), handler_class)

    httpd.serve_forever()

logger = logging.getLogger(__name__)
setup_logger(logger)
logger.setLevel(logging.DEBUG)

if __name__ == '__main__':
    main()