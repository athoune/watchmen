#!/usr/bin/env Rscript

tbl1 <- read.csv("scores.csv", sep="\t")
plot(tbl1$start, tbl1$time, ylab="time in ms")
hist(tbl1$time, 20, freq=FALSE, xlab="Time")
