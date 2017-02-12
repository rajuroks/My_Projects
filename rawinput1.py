print "How old are you?"
age = raw_input()
print "How tall are you"
height = raw_input()
print "how much do you weigh in lbs?"
weight_lb = raw_input()
weight_kg = (float (weight_lb) * 0.45359237)

print "So you are %r old %r tall and %r heavy in lbs and %r heavy in kg's." % (age, height, weight_lb, weight_kg)
