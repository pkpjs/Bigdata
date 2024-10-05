import matplotlib.pyplot as plt

def plot_results(results, malicious_counts):
    # 정확도 그래프
    models = list(results.keys())
    accuracies = [accuracy for accuracy, _ in results.values()]

    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.bar(models, accuracies, color='lightblue')
    plt.title('Model Accuracy')
    plt.xlabel('Model')
    plt.ylabel('Accuracy')
    plt.ylim(0, 1)

    # 악성 파일 개수 그래프
    plt.subplot(1, 2, 2)
    plt.bar(models, malicious_counts.values(), color='salmon')
    plt.title('Number of Malicious Files Detected')
    plt.xlabel('Model')
    plt.ylabel('Count')

    plt.tight_layout()
    plt.show()
