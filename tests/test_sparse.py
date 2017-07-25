from sklearn.feature_extraction import DictVectorizer

#v = DictVectorizer(sparse=True)
#D = [{'foo': 1, 'bar': 2}, {'foo': 3, 'baz': 1}]
#X = v.fit_transform(D)
#print X
#print v.inverse_transform(X)

#print v.transform({'foo': 4, 'unseen_feature': 3})


file_path = "/storage/emulated/0/Android/data/locat/locCache/app/14656868004645539.apk"

if "/sys/" in file_path or "/proc/" in file_path or '/data/app' in file_path or '/data/misc/keychain' in file_path or '.xml' in file_path:
    print file_path