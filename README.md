# OAuth2 Research

## Overview
This project shows the implementation of security feature that can be implemented on the top of existing OAuth2 protocol.


## Setting up Conventional OAuth Flow.

* Navigate to conventional-oauth directory.
* Install the node dependencies.
    >$> npm install
* Start the clientApp by issuing the below command in terminal.
  > $> npm run client
  ![Client App](/conventional-oauth/doc_imgs/client.gif)

* Start the Authorization server by issuing the below command in terminal.
  > $> npm run authz
   ![Client App](/conventional-oauth/doc_imgs/authz.gif)

* Start the ProtectedResource by issuing the below command in terminal.
  > $> npm run resserv
   ![Client App](/conventional-oauth/doc_imgs/res.gif)


## Setting up Proposed OAuth Flow Demo.

Follow the below steps for running the POC application of proposed_OAuth2.

* Navigate to proposed-oauth directory.
* Install the node dependencies.
    >$> npm install
* Start the clientApp by issuing the below command in terminal.
  > $> npm run clientApp 
    ![Client App](/proposed-oauth/docs_imgs/clientApp.gif)

*  Start the Verification Server by issuing the below command in terminal.
    > $> npm run verfi
![Verification Server](/proposed-oauth/docs_imgs/verif.gif)
*  Start the Authorization Server by issuing the below command in new  terminal window.
    > $> npm run authz 
    ![Verification Server](/proposed-oauth/docs_imgs/authz.gif)

* Start the Protected Resource Server by issuing the below command in new  terminal window.
    > $> npm run ressrv 
    ![Verification Server](/proposed-oauth/docs_imgs/resserv.gif)

* Visit http://127.0.0.1:9000 for running the demo.
  ![demo](/proposed-oauth/docs_imgs/demo.gif)

* Look into terminal for debug messages