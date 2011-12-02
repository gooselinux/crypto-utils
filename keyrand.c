/* 
   keyrand implementation using /dev/random
   Copyright (C) 2006 Red Hat, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <sys/types.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <slang/slang.h>
#include <newt.h>

static void collect_bytes(int fd, char *buffer, int total)
{
    int count;
    newtComponent title, form, scale;
    char message[1024];
    newtGrid box;

    box = newtCreateGrid(1, 3);

    snprintf(message, sizeof message,
             "To generate %u random bits from the "
             "kernel random number generator, some "
             "keyboard or mouse input may be necessary at the "
             "console for this host.  Please try entering "
             "some random text or moving the mouse, if "
             "running this program locally.", total * 8);
    
    title = newtTextboxReflowed(1, 1, message, 60, 10, 0, 0);
    
    newtGridSetField(box, 0, 0, NEWT_GRID_COMPONENT, title,
		     0, 0, 0, 0, 0, 0);
    
    /* The progress bar */
    scale = newtScale(0, 0, 30, total);
    newtScaleSet(scale, 0);
    
    newtGridSetField(box, 0, 1, NEWT_GRID_COMPONENT, scale,
		     0, 1, 0, 0, 0, 0);

    form = newtForm(NULL, NULL, 0);
    newtGridAddComponentsToForm(box, form, 1);
    
    newtGridWrappedWindow(box, "Collecting random data");
    
    newtDrawForm(form);

    count = 0;

    do {
        ssize_t rv;
        
        newtScaleSet(scale, count);
        newtRefresh();

        rv = read(fd, buffer + count, total - count);
        if (rv == -1 && errno == EINTR) continue;
        else if (rv < 0) {
            newtWinMessage("Error", "Exit", 
                           "Error reading from /dev/random");
            newtFinished();
            exit(1);
        }

	SLang_flush_input();
        count += rv;
    } while (count < total);

    newtFormDestroy(form);
}
    

int main(int argc, char **argv)
{
    const char *output;
    int bits, bytes, fd, rfd;
    char *buffer;

    if (argc < 3) {
        fprintf(stderr, "Usage: keyrand <number-of-bits> <output-file>\n");
        exit(1);
    }
    
    bits = atoi(argv[1]);
    output = argv[2];
    fd = open(output, O_APPEND|O_WRONLY);
    rfd = open("/dev/random", O_RDONLY);
    
    newtInit();
    newtCls();
    
    newtDrawRootText(0, 0, 
                     "Red Hat Keypair Generation (c) 2006 Red Hat, Inc.");
    
    if (fd < 0) {
        newtWinMessage("Error", "Exit", "Could not open output file");
        newtFinished();
        exit(1);
    }
    else if (rfd < 0) {
        newtWinMessage("Error", "Exit", "Could not open /dev/random");
        newtFinished();
        exit(1);
    }
    else if (bits < 8 || bits > 800 * 1024) {
        newtWinMessage("Error", "Exit", "More than 8 bits must be requested");
        newtFinished();
        exit(1);
    }
    
    bytes = bits / 8;
    buffer = malloc(bytes);
    sleep(1);

    collect_bytes(rfd, buffer, bytes);
    
    if (write(fd, buffer, bytes) != bytes || close(fd)) {
        newtWinMessage("Error", "Exit", "Error writing to random file");
        newtFinished();
        exit(1);
    }

    newtFinished();
    
    newtRefresh();

    sleep(1);
    newtPopWindow();
    SLang_flush_input();
    newtClearKeyBuffer();

    return 0;
}

