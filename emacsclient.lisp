;; we're going to use the unix-sockets library
;; https://quickref.common-lisp.net/unix-sockets.html
;; https://github.com/tdrhq/cl-unix-sockets/blob/master/unix-sockets.lisp

;; probably want to start out with a connect-unix-socket

(connect-unix-socket "/run/user/1000/emacs/server") ;; iirc
;; ok, let's now put that in a variable
(defparameter socket (connect-unix-socket "/run/user/1000/emacs/server"))
;; now we write something to it...
(format socket "...") ;; TODO: actually paste the sniffed communication into here
(close-unix-socket socket) ;; do we use "close" or "shutdown" here?
;; man i wish there were docs...