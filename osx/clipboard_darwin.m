#include <stdio.h>
#include <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#include "clipboard_darwin.h"

const char*
clipboard() {
    NSPasteboard*  myPasteboard  = [NSPasteboard generalPasteboard];
    NSString* myString = [myPasteboard  stringForType:NSPasteboardTypeString];
	const char *cstr = [myString UTF8String];
    return cstr;
}