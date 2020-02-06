/*
* add desigin pattern example
* */
public class DesignPattern {

    public static void testSingletonHungry() {

        SingletonHungry.getInstance().printf();
    }

    public static void testSingletonLazy() {

        SingletonLay.getInstance().printf();
    }

    public static void testStrategy() {

        ContextStrategy stategy1 = new ContextStrategy(new StudentStrategy());
        ContextStrategy stategy2 = new ContextStrategy(new TeacherStrategy());

        stategy1.printf();
        stategy2.printf();
    }

    public static void testAdapter() {

        ClassAdapter classAdapter = new ClassAdapter();

        ObjectAdapter objectAdapter = new ObjectAdapter(new StudentAdapter());

        classAdapter.run();
        classAdapter.fly();

        objectAdapter.run();
        objectAdapter.fly();
    }

    public static void main(String args[]) throws Exception {

//        testSingletonHungry();
//        testSingletonLazy();
//        testStrategy();
        testAdapter();
    }
}


/*********************************单例模式****************************************/
//单例模式-恶汉模式
 class SingletonHungry {

    //指向自己实例的私有静态引用
    private static SingletonHungry singletonHungry = new SingletonHungry();

    //私有的构造方法
    private SingletonHungry() {}

    //已自己实例为返回值的静态公有方法
    public static SingletonHungry getInstance() {

        return singletonHungry;
    }

    public void printf() {
        System.out.println("SingletonHungry");
    }
}

//单例模式-懒汉模式
class SingletonLay {

    //指向自己实例的私有静态引用
    private static SingletonLay singletonLazy;

    //私有的构造方法
    private SingletonLay() {}

    //已自己实例为返回值的静态公有方法
    public static SingletonLay getInstance() {

        if(null == singletonLazy) {
            synchronized(SingletonLay.class) {
                if(null == singletonLazy ) {
                    singletonLazy = new SingletonLay();
                }
            }
        }
        return singletonLazy;
    }

    public void printf() {
        System.out.println("SingletonLay");
    }
}

/*********************************策略模式****************************************/
interface IStrategy { //定义抽象策略类
    public void printf();
}

class StudentStrategy implements IStrategy { //定义具体策略实现类

    @Override
    public void printf() {
        System.out.println("StudentStrategy");
    }
}

class TeacherStrategy implements IStrategy { //定义具体策略实现类

    @Override
    public void printf() {
        System.out.println("TeacherStrategy");
    }
}

class ContextStrategy { //定义环境类

    private IStrategy strategy;

    public ContextStrategy(IStrategy strategy) {
        this.strategy = strategy;
    }

    public void printf() {
        strategy.printf();
    }
}

/*********************************适配器模式****************************************/
interface IAdapter { //被确定的目标接口

    public void run();
    public void fly();
}

class StudentAdapter { //被确定被适配者

    public void run() {
        System.out.println("StudentAdapter run");
    }
}

//类适配器
class ClassAdapter extends StudentAdapter implements IAdapter { //类适配器

    @Override
    public void fly() {
        System.out.println("ClassAdapter fly");
    }
}

class ObjectAdapter implements IAdapter { //对象适配器

    private StudentAdapter studentAdapter; //使用组合的方式,里面包含一个该类型的实例

    public ObjectAdapter(StudentAdapter s) {
        studentAdapter = s;
    }

    @Override
    public void run() {
        studentAdapter.run();
    }

    @Override
    public void fly() {
        System.out.println("ObjectAdapter fly");
    }
}