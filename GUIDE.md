This guide is intended to give tips and tricks for how to get the best tracing results.

1. Be concise.

Detecting anomalies in real-world programs is a battle between signal, noise, and the
memory capacity of the model. Most of the activity that goes on in a program is going
to be normal, even when the program is under attack. Therefore, the shorter and more relevant
you can keep your traces, the better results you'll get.

For example, if you're interested in a program that views files, like Acrobat Reader or Microsoft
Word, avoid tracing the initialization phase of the program. This is all pre-attack
activity (the input file in question hasn't even been opened yet) so it isn't relevant to the
anomalies you're trying to detect. This can be accomplished by writing a job script that starts
the program, sleeps for a generous number of seconds, and then opens the input file.

Similarly, if you know attacks will be carried out quickly, limit the duration of your trace
accordingly. For example, malicious Word macros rarely sleep, so setting the `runtime` in your
agent config to 60 seconds is more than enough. You don't need to trace for 2 minutes.

2. Do you really need a monkey?

Monkeys are sometimes necessary to trigger malware, but not always. For example, many Word
document malware will ask the user to enable active content so their malicious macros execute.
You could use a monkey to simulate these user steps, or you can simply disable the security
options in Word's settings. Monkeys click random GUI elements, which invoke callbacks, and
ultimately generate normal activity not relevant to attacks. Therefore, if you can avoid
using a monkey, do so. Once again, be concise.
