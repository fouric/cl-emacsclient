(in-package :cl-emacsclient)

(declaim (optimize (speed 0) (safety 0) (space 0) (debug 3)))

;; we're going to use the unix-sockets library
;; https://quickref.common-lisp.net/unix-sockets.html
;; https://github.com/tdrhq/cl-unix-sockets/blob/master/unix-sockets.lisp

;; probably want to start out with a connect-unix-socket

(defun emacsclient ()
  ;; ok, let's now put that in a variable
  (defparameter socket (connect-unix-socket "/run/user/1000/emacs/server"))
  ;; now we write something to it...
  (format socket "-dir /home/fouric/ -current-frame -eval (<&_1&_(length&_(frame-list)))~%") ;; TODO: actually paste the sniffed communication into here
  ;; can't do this, "socket" isn't a CL stream that you can write to
  ;; maybe this will help?
  (unix-socket-stream socket)
  ;; ok, now let's try
  (write-line "-dir /home/fouric/ -current-frame -eval (<&_1&_(length&_(frame-list)))" (unix-socket-stream socket))
  ;; There is no applicable method for the generic function
  ;; #<SB-GRAY::STREAM-FUNCTION COMMON-LISP:STREAM-ELEMENT-TYPE (4)>
  ;; when called with arguments
  ;; (#<UNIX-SOCKETS::INTERNAL-STREAM {1004D3B5C3}>).
  ;; [Condition of type SB-PCL::NO-APPLICABLE-METHOD-ERROR]

  ;; is it possible that the unix-sockets library is incomplete?
  (close-unix-socket socket) ;; do we use "close" or "shutdown" here?
  ;; man i wish there were docs...(in-package :ql-system)
  )
