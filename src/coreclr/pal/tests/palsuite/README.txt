; Licensed to the .NET Foundation under one or more agreements.
; The .NET Foundation licenses this file to you under the MIT license.

===========================================================================


1.   ENVIRONMENT SETUP

2.   RUNNING THE SUITES

3.   ENVIRONMENT VARIABLES AND AUTOMATED TESTING SPECIFICS

4.   ADDITIONAL NOTES ON TESTING/SPECIFIC TEST CASE ISSUES
     File_IO: getfilesize/test1, setfilepointer/test(5,6,7)
     Pal_specific:: pal_get_stdin/test1, pal_get_stdout/test1, pal_get_stderr/test1
     Threading: setconsolectrlhandler/test(3,4)


===========================================================================

1.  ENVIRONMENT SETUP
~~~~~~~~~~~~~~~~~~~~~

Within a Rotor build window (env.sh/env.csh/env.bat), no additional
configuration needs to be done.


2. RUNNING THE SUITES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run %ROTOR_DIR%\tests\pvtrun.pl to launch the test suites.  It will
display information about each test as it runs, then report a
summary of the results upon completion.

The results are logged to %ROTOR_DIR%\tests\pvtResults.log.


3. ENVIRONMENT VARIABLES AND AUTOMATED TESTING SPECIFICS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See notes in section 4 on the following test cases if running automated tests:

     Threading: setconsolectrlhandler/test(3,4)


4. ADDITIONAL NOTES ON TESTING/SPECIFIC TEST CASE ISSUES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

File_IO: getfilesize/test1, getfilesizeex/test1 setfilepointer/test(5,6,7)

These tests cases create a large number of temporary files which require
ample disk space.  On systems with less than 6Gb free disk space expect
these test cases to fail.


ic: pal_get_stdin/test1, pal_get_stdout/test1, pal_get_stderr/test1

These test cases should be manually inspected to ensure the information being returned
is correct.  The pal_get_stdin test case requires user input.  The pal_get_stdout and
pal_get_stderr test cases do not require user input, but their output should be inspected
to verify that correct messages are being displayed.


Threading: setconsolectrlhandler/test(3,4)

These test cases require user response in order to produce a meaningful results.
For automated testing, this test case is disabled.
