library(readr) # provides a fast and friendly way to read csv data

# A function to load multiple .CSV files in a directory
loadData<-function(dirPath){ 
  dirPath<- directory.path
  fileList <- list.files(dirPath, pattern=".csv",full.names = TRUE)
  for (eachFile in fileList){
    if (!exists("tmpDataset")){
      tmpDataset <- read.csv(eachFile,header = T)
    } else if (exists("tmpDataset")){
      tempData <-read.csv(eachFile,header = T)
      tmpDataset<-rbind(tmpDataset, tempData)
    }}
  return(tmpDataset)
}

# Load the benign traffic data from the publisher location
benginDataset<- read_csv("https://archive.ics.uci.edu/ml/machine-learning-databases/00442/Danmini_Doorbell/bengin_traffic.csv")

# Download, .RARs that contains malicious traffic from the publisher location, and extract and read data
devtools::install_github("jimhester/archive") # install archive package
library(archive)

temp_file1 <- tempfile(fileext = ".rar")
download.file("https://archive.ics.uci.edu/ml/machine-learning-databases/00442/Danmini_Doorbell/gafgyt_attacks.rar", temp_file1) # Load the gafgyt data
temp_file2 <- tempfile()
archive_extract(temp_file1, temp_file2)
directory.path<-temp_file2
gafgytDataset<-loadData(directory.path)
unlink(temp_file1)
unlink(temp_file2)

temp_file1 <- tempfile(fileext = ".rar")
download.file("https://archive.ics.uci.edu/ml/machine-learning-databases/00442/Danmini_Doorbell/mirai_attacks.rar", temp_file1) # Load the mirai traffic data
temp_file2 <- tempfile()
archive_extract(temp_file1, temp_file2)
directory.path<-temp_file2
miraiDataset<-loadData(directory.path)
unlink(temp_file1)
unlink(temp_file2)

# Removing records in the dataset that contain NAs
benginDataset<-benginDataset[complete.cases(benginDataset), ]
gafgytDataset<-gafgytDataset[complete.cases(gafgytDataset), ]
miraiDataset<-miraiDataset[complete.cases(miraiDataset), ]

# Adding labels to the data, benign traffic is marked as TRUE, and malicious traffic as FALSE
benginDataset$Type<-TRUE
gafgytDataset$Type<-FALSE
miraiDataset$Type<-FALSE

# Preparing the dataset, split at random the benign dataset into two subsets --- one with 80% of the instances for training, and another with the remaining 20%; the remaining 20% is merged with malicious instances for testing
index <- 1:nrow(benginDataset)
testIndex <- sample(index, trunc(length(index)*20/100))
testSetBen <- benginDataset[testIndex,] # Create the Benign class for testing
testSet <- rbind(gafgytDataset,miraiDataset,testSetBen) # Pool the benign test instances with malicious instances to create the final testing dataset
trainSet <- benginDataset[-testIndex,] # Create the training set, this set contains benign instances only

# R code snippet for training the OCSVM
library(kernlab)
fit <- ksvm(Type~., data=trainSet, type="one-svc", kernel="rbfdot", kpar="automatic")
print(fit) # To print model details

# Model evaluation (OCSVM)
library(caret)
predictions <- predict(fit, testSet[,1:(ncol(testSet)-1)], type="response") # make predictions
confusionMatrix(data=as.factor(predictions),reference=as.factor(testSet$Type)) # summarize the accuracy

# R code snippet for training the Autoencoder
library(h2o) # We will use h2o package for running h2o’s deep learning via its REST API
#h2o.removeAll() # To remove previous connections, if any
h2o.init(nthreads = -1) # To use all cores
data<-trainSet[,-116] # Take a copy of training data without labels
trainH2o<-as.h2o(data, destination_frame="trainH2o.hex") # Convert data to h20 compatible format

# Building a deep autoencoder learning model using trainH2o, i.e. only using "benign" instances, and using “Bottleneck” training with random choice of number of hidden layers
train.IoT <- h2o.deeplearning(x = names(trainH2o), training_frame = trainH2o, activation = "Tanh", autoencoder = TRUE, hidden = c(50,2,50), l1 = 1e-4, epochs = 100, variable_importances=T, model_id = "train.IoT", reproducible = TRUE, ignore_const_cols = FALSE, seed = 123)
h2o.saveModel(train.IoT, path="train.IoT", force = TRUE) # Better to save the model as it may take time to train it – depends on the performance of your machine
train.IoT <- h2o.loadModel("./train.IoT/train.IoT") # load the model
train.IoT # To print model details

train.anon = h2o.anomaly(train.IoT, trainH2o, per_feature=FALSE) # calculate MSE across training observations
head(train.anon) # Print a sample of MSE values
err <- as.data.frame(train.anon)
plot(sort(err[,1]), main='Reconstruction Error',xlab="Row index", ylab="Reconstruction.MSE",col="orange")

threshold<-0.02 # Define the threshold based on Reconstruction.MSE of training

train.IoT <- h2o.loadModel("./train.IoT/train.IoT") # load the model
newtestSet<-testSet[sample(nrow(testSet), 976829 %/% 2), ] # Here we select randomly 50% records of test instances due to the memory limitation of our computer, this step not necessary if you have enough memory on your machine / or run this section multiple times, and summarise (average) the results to approximate the accuracy if your computer has low computationally resources
data<-newtestSet[,-116] # remove labels from the test data frame
testH2o<-as.h2o(data, destination_frame="trainH2o.hex") #convert data to h20 compatible
test.anon = h2o.anomaly(train.IoT,testH2o, per_feature=FALSE) # calculate MSE across observations
err <- as.data.frame(test.anon)
prediction <- err$Reconstruction.MSE<=threshold
confusionMatrix(data=as.factor(prediction),reference=as.factor(newtestSet$Type)) # summarize the accuracy
