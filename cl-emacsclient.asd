;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

(defpackage #:cl-emacsclient-asd
  (:use :cl :asdf))

(in-package :cl-emacsclient-asd)

(defsystem cl-emacsclient
  :name "cl-emacsclient"
  :version "0.0.0"
  :maintainer "fouric"
  :author "fouric"
  :license "GNU GPL v3"
  :description "A Common Lisp implementation of emacsclient"

  :serial t
  :depends-on (:unix-sockets)
  :components ((:file "package")
               (:file "emacsclient" :depends-on ("package"))))
